using System.IO.Enumeration;
using System.Runtime.InteropServices;
using System.Text;
using AntiGrabber.Service.Network;
using AntiGrabber.Shared;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace AntiGrabber.Service.FileWatch;

/// Vê QUEM abre cada arquivo sensível via ETW (Microsoft-Windows-Kernel-File, evento
/// Create): PID + caminho em toda abertura, inclusive leitura de 1ms — coisa que
/// FileSystemWatcher (depende do LastAccess do NTFS) e Restart Manager (só vê arquivo
/// ainda aberto) não pegam. Dono do arquivo e leitor confiável do Windows são ignorados;
/// o resto vira correlação, e arquivo de conta (AccountData) bloqueia a rede do processo.
public sealed class TokenFileWatcher : BackgroundService
{
    private static readonly Guid KernelFileProvider = new("EDD08927-9CC4-4E65-B970-C2560FB5C289");
    private const ulong KernelFileKeywordCreate = 0x80;
    private const int CreateEventId = 12;

    public sealed record WatchedPath(string Path, SensitiveAppDefinition App);

    private readonly ILogger<TokenFileWatcher> _logger;
    private readonly CorrelationTracker _correlationTracker;

    public TokenFileWatcher(ILogger<TokenFileWatcher> logger, CorrelationTracker correlationTracker)
    {
        _logger = logger;
        _correlationTracker = correlationTracker;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var volumes = DosToNtVolumes();
        var watched = new UnifiedAppLocator().DetectAll()
            .SelectMany(install => install.SensitiveDirectories.Select(path => (install, path)))
            .Select(x => new WatchedPath(ToNtPath(x.path, volumes) ?? x.path, SensitiveAppCatalog.Apps.Single(a => a.AppId == x.install.AppId)))
            .ToList();

        _logger.LogInformation(
            "TokenFileWatcher observando {Count} caminhos sensíveis ({Accounts} de conta) via ETW.",
            watched.Count, watched.Count(w => w.App.AccountData));
        if (watched.Count == 0) return Task.CompletedTask;

        return Task.Run(() => RunSession(watched, volumes, stoppingToken), stoppingToken);
    }

    private void RunSession(IReadOnlyList<WatchedPath> watched, IReadOnlyDictionary<string, string> volumes, CancellationToken ct)
    {
        try
        {
            var ownPid = Environment.ProcessId;
            RunEtw("AntiGrabber-SensitiveFiles", watched, (pid, fileName, hit) =>
            {
                if (pid != ownPid) OnSensitiveOpen(pid, ToDosPath(fileName, volumes), hit.App);
            }, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _logger.LogError(ex, "Sessão ETW de arquivos sensíveis falhou — leitura de conta não será vigiada.");
        }
    }

    /// Bloqueia até ct cancelar. Precisa de admin. Público pro cenário etw-smoke do TestHarness.
    public static void RunEtw(string sessionName, IReadOnlyList<WatchedPath> watched, Action<int, string, WatchedPath> onOpen, CancellationToken ct)
    {
        using var session = new TraceEventSession(sessionName);
        using var stop = ct.Register(() => session.Dispose());
        _activeSession = session;
        session.EnableProvider(KernelFileProvider, TraceEventLevel.Informational, KernelFileKeywordCreate);

        // Kernel-File é provider de manifesto registrado no Windows → parser via TDH.
        new RegisteredTraceEventParser(session.Source).All += e =>
        {
            // Marca d'água: o handler é síncrono e em ordem, então ver um evento com horário T
            // garante que toda leitura de conta anterior a T já foi processada.
            Interlocked.Exchange(ref _watermarkUtcTicks, e.TimeStamp.ToUniversalTime().Ticks);
            if ((int)e.ID != CreateEventId || e.ProcessID <= 4) return;
            if (e.PayloadByName("FileName") is not string fileName) return;
            if (Match(fileName, watched) is { } hit) onOpen(e.ProcessID, fileName, hit);
        };

        // Entrega em tempo real tem ~1s de buffer do ETW; stealer que lê e manda no mesmo
        // segundo passaria antes do registro. O NetworkFilterWorker segura a conexão de code
        // host por um instante e chama FlushEtw() pra fechar essa corrida.
        // ponytail: callback síncrono do kernel (minifilter) eliminaria a espera.
        try { session.Source.Process(); }
        finally { _activeSession = null; }
    }

    private static volatile TraceEventSession? _activeSession;
    private static long _watermarkUtcTicks;

    public static bool EtwActive => _activeSession is not null;

    /// Horário (UTC) do evento ETW mais recente já processado.
    public static DateTime EtwWatermarkUtc => new(Interlocked.Read(ref _watermarkUtcTicks), DateTimeKind.Utc);

    /// Força o ETW a entregar agora os eventos em buffer (em vez de esperar o timer de ~1s).
    public static void FlushEtw()
    {
        try { _activeSession?.Flush(); }
        catch { /* sessão fechando — a espera do chamador cobre o resto */ }
    }

    public static IReadOnlyDictionary<string, string> VolumeMap() => DosToNtVolumes();

    private void OnSensitiveOpen(int pid, string path, SensitiveAppDefinition app)
    {
        var info = BlockInvestigator.ProcessInfo.TryRead(pid);
        var processName = info?.ImagePath is { } image ? Path.GetFileName(image) : null;
        if (IsTrustedSystemReader(info?.ImagePath) || IsOwner(app, processName, info?.CommandLine)) return;

        if (app.AccountData)
        {
            _correlationTracker.RecordAccountRead(pid, path, app.DisplayName);
            _logger.LogWarning(
                "Arquivo de conta de {App} aberto por {Process} (pid={Pid}): {FileName} — rede desse processo bloqueada por {Seconds}s.",
                app.DisplayName, processName ?? "desconhecido", pid, Path.GetFileName(path), CorrelationTracker.AccountReadWindow.TotalSeconds);
        }
        else
        {
            _correlationTracker.RecordFileAccess(pid, path);
            _logger.LogInformation(
                "Acesso a diretório sensível de {App} por {Process} (pid={Pid}): {FileName}",
                app.DisplayName, processName ?? "desconhecido", pid, Path.GetFileName(path));
        }
    }

    /// Caminho vigiado pode ser diretório (tudo dentro conta), arquivo, ou curinga no
    /// último trecho ("ssfn*", "app.db*").
    public static WatchedPath? Match(string fileName, IReadOnlyList<WatchedPath> watched)
    {
        foreach (var w in watched)
        {
            if (fileName.Equals(w.Path, StringComparison.OrdinalIgnoreCase)
                || fileName.StartsWith(w.Path + "\\", StringComparison.OrdinalIgnoreCase))
                return w;

            var pattern = Path.GetFileName(w.Path);
            if (pattern.Contains('*')
                && string.Equals(Path.GetDirectoryName(fileName), Path.GetDirectoryName(w.Path), StringComparison.OrdinalIgnoreCase)
                && FileSystemName.MatchesSimpleExpression(pattern, Path.GetFileName(fileName)))
                return w;
        }
        return null;
    }

    /// Dono do arquivo: processo do próprio launcher. Launcher em Java (javaw) só conta
    /// como dono se a linha de comando citar o launcher E não for o jogo — o jogo roda no
    /// mesmo javaw.exe com mods de terceiros dentro.
    public static bool IsOwner(SensitiveAppDefinition app, string? processName, string? commandLine)
    {
        if (processName is null) return false;
        if (!DomainWhitelistStore.IsCodeHost(processName))
            return app.ProcessNames.Contains(processName, StringComparer.OrdinalIgnoreCase);

        return commandLine is not null
            && (processName.Equals("java.exe", StringComparison.OrdinalIgnoreCase) || processName.Equals("javaw.exe", StringComparison.OrdinalIgnoreCase))
            && app.OwnerCommandLineHints is { } hints
            && hints.Any(h => commandLine.Contains(h, StringComparison.OrdinalIgnoreCase))
            && !commandLine.Contains("--gameDir", StringComparison.OrdinalIgnoreCase)
            && !commandLine.Contains("--accessToken", StringComparison.OrdinalIgnoreCase);
    }

    // Leitores do próprio Windows (antivírus, indexador, Explorer) abrem tudo o tempo todo.
    // Nome sozinho dá pra forjar — só vale dentro de pasta que exige admin pra escrever.
    private static readonly (string Name, string[] Dirs)[] TrustedReaders =
    {
        ("MsMpEng.exe", new[] { @"%ProgramFiles%\Windows Defender\", @"%ProgramData%\Microsoft\Windows Defender\Platform\" }),
        ("MpDefenderCoreService.exe", new[] { @"%ProgramFiles%\Windows Defender\", @"%ProgramData%\Microsoft\Windows Defender\Platform\" }),
        ("SearchProtocolHost.exe", new[] { @"%SystemRoot%\System32\" }),
        ("SearchIndexer.exe", new[] { @"%SystemRoot%\System32\" }),
        ("SearchFilterHost.exe", new[] { @"%SystemRoot%\System32\" }),
        ("explorer.exe", new[] { @"%SystemRoot%\" }),
    };

    public static bool IsTrustedSystemReader(string? imagePath)
    {
        if (imagePath is null) return false;
        var name = Path.GetFileName(imagePath);
        return TrustedReaders.Any(t => t.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
            && t.Dirs.Any(d => imagePath.StartsWith(Environment.ExpandEnvironmentVariables(d), StringComparison.OrdinalIgnoreCase)));
    }

    /// ETW entrega caminho de dispositivo (\Device\HarddiskVolume3\Users\...). Converte o
    /// caminho vigiado uma vez pra esse formato, em vez de converter cada evento.
    public static string? ToNtPath(string dosPath, IReadOnlyDictionary<string, string> volumes)
    {
        if (dosPath.Length < 2 || dosPath[1] != ':') return null;
        return volumes.TryGetValue(dosPath[..2].ToUpperInvariant(), out var device) ? device + dosPath[2..] : null;
    }

    public static string ToDosPath(string ntPath, IReadOnlyDictionary<string, string> volumes)
    {
        foreach (var (drive, device) in volumes)
            if (ntPath.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                return drive + ntPath[device.Length..];
        return ntPath;
    }

    private static Dictionary<string, string> DosToNtVolumes()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var buffer = new StringBuilder(1024);
        foreach (var drive in DriveInfo.GetDrives())
        {
            var letter = drive.Name[..2].ToUpperInvariant();
            if (QueryDosDevice(letter, buffer, buffer.Capacity) > 0) map[letter] = buffer.ToString();
        }
        return map;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);
}
