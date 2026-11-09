using System.Collections.Concurrent;
using AntiGrabber.Service.Ipc;
using AntiGrabber.Shared;

namespace AntiGrabber.Service.Network;

/// Scan proativo de mods do Minecraft. Mod rodando dentro do jogo recebe o token pela
/// memória (--accessToken), não lê arquivo de conta — então o bloqueio "leu conta" nunca
/// dispara pra ele, e um envio pro servidor próprio do autor passava. Aqui cada jar das
/// pastas de mods é escaneado ANTES de qualquer conexão: na subida do serviço e na hora
/// em que um jar novo/alterado cai na pasta. Jar com indicador (token de sessão + envio,
/// webhook, arquivo de conta...) marca a pasta; o javaw que carrega essa pasta fica sem
/// rede (fora Mojang/Microsoft) enquanto o jar estiver lá. Tirou o jar, volta ao normal.
public sealed class ModGuard : BackgroundService
{
    // Raízes por perfil de usuário onde ficam pastas "mods" (oficial/TLauncher, Prism,
    // PolyMC, Modrinth, CurseForge). Busca até MaxDepth abaixo de cada raiz.
    // ponytail: pasta de instâncias customizada no launcher, MultiMC/ATLauncher portáteis e
    // Lunar/Feather ficam de fora do scan proativo — o javaw delas ainda é coberto na hora
    // de conectar (a espera do code host aguarda o scan da pasta de mods do processo).
    private static readonly string[] ModRoots =
    [
        @"AppData\Roaming\.minecraft",
        @"AppData\Roaming\PrismLauncher\instances",
        @"AppData\Roaming\PolyMC\instances",
        @"AppData\Roaming\ModrinthApp\profiles",
        @"curseforge\minecraft\Instances",
    ];
    private const int MaxDepth = 3;
    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
        { "assets", "libraries", "versions", "logs", "crash-reports", "saves", "resourcepacks", "shaderpacks", "screenshots", "natives", ".git" };

    private readonly ILogger<ModGuard>? _logger;
    private readonly IpcServer? _ipc;
    private readonly Func<string, FileFindingPayload?> _scan;
    private readonly ConcurrentDictionary<string, (string ModsDir, FileFindingPayload Finding)> _flagged = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Task> _scannedDirs = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, (DateTime When, IReadOnlyList<string> Dirs)> _dirsByPid = new();
    private readonly List<FileSystemWatcher> _watchers = new();

    public ModGuard(ILogger<ModGuard> logger, BlockInvestigator investigator, IpcServer ipc)
        : this(path => investigator.ScanCached(path).Finding, logger, ipc) { }

    /// Pro self-test: scanner injetado, sem IPC nem log.
    public ModGuard(Func<string, FileFindingPayload?> scan, ILogger<ModGuard>? logger = null, IpcServer? ipc = null)
    {
        _scan = scan;
        _logger = logger;
        _ipc = ipc;
    }

    public bool AnyFlagged => !_flagged.IsEmpty;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield(); // varredura de pastas fora da thread de startup do host
        var roots = UnifiedAppLocator.UserProfileDirectories()
            .SelectMany(profile => ModRoots.Select(r => Path.Combine(profile, r)))
            .Where(Directory.Exists)
            .ToList();

        foreach (var root in roots) Watch(root);

        var dirs = roots.SelectMany(r => FindModsDirs(r, MaxDepth)).ToList();
        foreach (var dir in dirs)
        {
            if (stoppingToken.IsCancellationRequested) break;
            await EnsureScanned(dir);
        }
        _logger?.LogInformation("ModGuard: {Dirs} pasta(s) de mods vigiadas, {Flagged} mod(s) suspeito(s).", dirs.Count, _flagged.Count);

        try { await Task.Delay(Timeout.Infinite, stoppingToken); }
        catch (OperationCanceledException) { }
        foreach (var w in _watchers) w.Dispose();
    }

    /// Mods suspeitos carregados por esse javaw (pelas pastas de mods dele). Pasta que
    /// ainda não foi escaneada (fora das raízes conhecidas) é escaneada agora em segundo
    /// plano — até terminar, conta como limpa.
    public FileFindingPayload[] FlaggedFor(int pid, string processName) => FlaggedIn(DirsOf(pid, processName));

    /// Scan de alguma pasta de mods desse javaw ainda rodando — a espera do code host no
    /// NetworkFilterWorker aguarda isso (com teto) pra não decidir com a pasta não lida.
    public bool ScanPendingFor(int pid, string processName) =>
        DirsOf(pid, processName).Any(d => !EnsureScanned(d).IsCompleted);

    private IReadOnlyList<string> DirsOf(int pid, string processName)
    {
        var now = DateTime.UtcNow;
        if (!_dirsByPid.TryGetValue(pid, out var cached) || now - cached.When > TimeSpan.FromMinutes(10))
        {
            cached = (now, BlockInvestigator.ModDirsOf(pid, processName));
            _dirsByPid[pid] = cached;
        }
        foreach (var dir in cached.Dirs) _ = EnsureScanned(dir);
        return cached.Dirs;
    }

    public FileFindingPayload[] FlaggedIn(IEnumerable<string> modsDirs)
    {
        var set = new HashSet<string>(modsDirs.Select(Normalize), StringComparer.OrdinalIgnoreCase);
        return _flagged.Values.Where(f => set.Contains(f.ModsDir)).Select(f => f.Finding).ToArray();
    }

    public Task EnsureScanned(string modsDir) =>
        _scannedDirs.GetOrAdd(Normalize(modsDir), dir => Task.Run(() =>
        {
            IEnumerable<string> jars;
            try { jars = Directory.EnumerateFiles(dir, "*.jar").ToList(); }
            catch { return; }
            foreach (var jar in jars) OnJarChanged(jar);
        }));

    /// Jar novo/alterado: escaneia e marca (ou desmarca, se a versão nova veio limpa).
    public void OnJarChanged(string jarPath)
    {
        if (ModsDirOf(jarPath) is not { } modsDir) return;
        FileFindingPayload? finding;
        try { finding = _scan(jarPath); }
        catch { return; } // ainda sendo gravado/travado — o próximo evento de mudança reescaneia

        if (finding is null)
        {
            _flagged.TryRemove(jarPath, out _);
            return;
        }

        // Created+Changed chegam juntos pro mesmo jar: TryAdd garante um aviso só.
        if (_flagged.TryAdd(jarPath, (modsDir, finding))) _ = AnnounceAsync(finding);
        else _flagged[jarPath] = (modsDir, finding);
    }

    public void OnJarRemoved(string jarPath)
    {
        if (_flagged.TryRemove(jarPath, out var removed))
            _logger?.LogInformation("Mod suspeito removido da pasta: {Path} — rede do jogo liberada pra essa pasta.", jarPath);
    }

    /// Pasta "mods" que contém o jar (o próprio pai, ou um ancestral pra mods/<versão>/x.jar).
    public static string? ModsDirOf(string jarPath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(jarPath));
        for (var i = 0; dir is not null && i < 3; i++, dir = Path.GetDirectoryName(dir))
            if (Path.GetFileName(dir).Equals("mods", StringComparison.OrdinalIgnoreCase)) return Normalize(dir);
        return null;
    }

    public static IEnumerable<string> FindModsDirs(string root, int maxDepth)
    {
        var queue = new Queue<(string Dir, int Depth)>();
        queue.Enqueue((root, 0));
        while (queue.Count > 0)
        {
            var (dir, depth) = queue.Dequeue();
            string[] subs;
            try { subs = Directory.GetDirectories(dir); }
            catch { continue; }
            foreach (var sub in subs)
            {
                var name = Path.GetFileName(sub);
                if (name.Equals("mods", StringComparison.OrdinalIgnoreCase)) yield return Normalize(sub);
                else if (depth < maxDepth && !SkipDirs.Contains(name)) queue.Enqueue((sub, depth + 1));
            }
        }
    }

    private static string Normalize(string dir) => Path.GetFullPath(dir).TrimEnd('\\', '/');

    private void Watch(string root)
    {
        try
        {
            var w = new FileSystemWatcher(root, "*.jar")
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
            };
            w.Created += (_, e) => Debounced(e.FullPath);
            w.Changed += (_, e) => Debounced(e.FullPath);
            w.Renamed += (_, e) => { OnJarRemoved(e.OldFullPath); Debounced(e.FullPath); };
            w.Deleted += (_, e) => OnJarRemoved(e.FullPath);
            // Estouro do buffer (cópia de modpack inteiro): reescaneia as pastas da raiz.
            w.Error += (_, _) =>
            {
                foreach (var dir in FindModsDirs(root, MaxDepth))
                {
                    _scannedDirs.TryRemove(dir, out _);
                    _ = EnsureScanned(dir);
                }
            };
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Não foi possível vigiar {Root}.", root);
        }
    }

    // Jar sendo copiado dispara vários eventos: espera assentar antes de ler.
    private void Debounced(string path) => _ = Task.Delay(1500).ContinueWith(_ =>
    {
        if (File.Exists(path)) OnJarChanged(path);
    });

    private async Task AnnounceAsync(FileFindingPayload finding)
    {
        var name = finding.ModName ?? Path.GetFileName(finding.Path);
        _logger?.LogWarning(
            "Mod suspeito na pasta: {Mod} ({Path}) — {Indicators}. O jogo que carregar essa pasta fica sem rede (fora Mojang/Microsoft) enquanto ele estiver lá.",
            name, finding.Path, string.Join("; ", finding.Indicators.Select(i => i.Label).Distinct()));
        if (_ipc is null) return;
        try
        {
            await _ipc.PublishAsync(new IpcEnvelope
            {
                Type = IpcMessageType.BlockEvent,
                BlockEvent = new BlockEventPayload
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    ProcessName = name,
                    Domain = "",
                    Protocol = "MOD",
                    CorrelatedFilePath = finding.Path,
                    PlainLanguageMessage =
                        $"Mod suspeito encontrado: {name} pode roubar sua conta do Minecraft. " +
                        "Enquanto ele estiver na pasta de mods, o jogo não fala com a internet (fora Mojang/Microsoft). " +
                        $"Remova o arquivo: {finding.Path}",
                    Investigation = new InvestigationPayload
                    {
                        Timestamp = DateTimeOffset.Now,
                        ProcessName = name,
                        Findings = [finding],
                        FilesScanned = 1,
                        Context = Path.GetDirectoryName(finding.Path),
                    },
                },
            });
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Falha avisando a bandeja sobre mod suspeito.");
        }
    }
}
