using System.Collections.Concurrent;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AntiGrabber.Service.Ipc;
using AntiGrabber.Shared;

namespace AntiGrabber.Service.Network;

/// Depois de um bloqueio, junta em segundo plano tudo que dá pra saber do processo
/// (caminho, hash, assinatura, pai, início) e, se for host de código (java, python,
/// node, powershell...), acha os jars/scripts que ele roda e procura indicadores de
/// stealer — registrando o link/webhook EXATO achado pra validação manual. Só
/// documenta: nunca bloqueia, move ou desativa nada, e nunca atrasa o filtro de rede.
/// O path /api/webhooks viaja cifrado no TLS (sem MITM), por isso a busca é nos arquivos.
public sealed class BlockInvestigator
{
    private static readonly TimeSpan ReinspectAfter = TimeSpan.FromMinutes(10);
    private const long MaxEntryBytes = 16 * 1024 * 1024;
    private const int MaxHitsPerFile = 50;

    private enum Expand { None, UrlLeft, Context }

    private sealed record Indicator(string Label, Regex Pattern, Expand Expand = Expand.None, bool IsBase64 = false);

    // Regex só no núcleo (literal na frente = rápido); o trecho ao redor (esquema/subdomínio
    // da URL, ou o texto legível em volta) é estendido à mão em ExpandMatch — contexto via
    // regex tipo [ -~]{0,160} no início faz backtracking em cada posição e trava jar grande.
    private static readonly Indicator[] Indicators =
    [
        new("URL de webhook do Discord", new(@"discord(?:app)?\.com/api/(?:v\d+/)?webhooks[\w/\-.?=&%]*", RegexOptions.IgnoreCase), Expand.UrlLeft),
        new("URL de webhook do Discord em base64", new("(?:" + string.Join("|",
            Base64Prefix("https://discord.com/api/webhooks"),
            Base64Prefix("https://discordapp.com/api/webhooks"),
            Base64Prefix("https://canary.discord.com/api/webhooks"),
            Base64Prefix("https://ptb.discord.com/api/webhooks"),
            Base64Prefix("discord.com/api/webhooks")) + ")[A-Za-z0-9+/]*={0,2}"), IsBase64: true),
        new("caminho de token do Discord", new(@"Local Storage[\\/]+leveldb|dQw4w9WgXcQ:", RegexOptions.IgnoreCase), Expand.Context),
        new("credenciais de navegador", new(@"Login Data|encrypted_key"), Expand.Context),
        new("bot do Telegram", new(@"api\.telegram\.org/bot[\w:\-/?=&%.]*", RegexOptions.IgnoreCase), Expand.UrlLeft),
        new("indicador do Fractureiser", new(@"files-8ie\.pages\.dev|85\.217\.144\.130|dev/neko/nek"), Expand.Context),
    ];

    private readonly ILogger<BlockInvestigator> _logger;
    private readonly IpcServer _ipcServer;
    private readonly ConcurrentDictionary<int, (DateTime When, InvestigationPayload? Result)> _byPid = new();
    private readonly ConcurrentDictionary<string, FileFindingPayload?> _fileCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string?> _hashCache = new(StringComparer.OrdinalIgnoreCase);

    public BlockInvestigator(ILogger<BlockInvestigator> logger, IpcServer ipcServer)
    {
        _logger = logger;
        _ipcServer = ipcServer;
    }

    /// Investigação já pronta pra esse PID (bloqueios repetidos do mesmo processo
    /// chegam na bandeja já com os detalhes).
    public InvestigationPayload? TryGetCached(int pid)
        => _byPid.TryGetValue(pid, out var e) && DateTime.UtcNow - e.When < ReinspectAfter ? e.Result : null;

    public void InvestigateBlock(int pid, string processName, string domain)
    {
        var now = DateTime.UtcNow;
        if (_byPid.TryGetValue(pid, out var last) && now - last.When < ReinspectAfter) return;
        _byPid[pid] = (now, null);

        _ = Task.Run(async () =>
        {
            try
            {
                var result = Investigate(pid, processName, domain);
                _byPid[pid] = (now, result);
                LogInvestigation(result);
                await _ipcServer.PublishAsync(new IpcEnvelope { Type = IpcMessageType.InvestigationEvent, Investigation = result });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha investigando {Process} (pid={Pid}).", processName, pid);
            }
        });
    }

    private InvestigationPayload Investigate(int pid, string processName, string domain)
    {
        var result = new InvestigationPayload
        {
            Timestamp = DateTimeOffset.Now,
            Pid = pid,
            ProcessName = processName,
            Domain = domain,
        };

        var info = ProcessInfo.TryRead(pid);
        if (info is null)
        {
            result.Note = "Processo já tinha fechado — sem detalhes.";
            return result;
        }

        result.ProcessPath = info.ImagePath;
        result.ProcessStartTime = info.StartTime;
        if (info.ImagePath is not null)
        {
            result.ProcessSha256 = Sha256Cached(info.ImagePath);
            result.ProcessSigned = BinaryIntegrityChecker.VerifySignature(info.ImagePath);
            result.ProcessSigner = TryGetSigner(info.ImagePath);
        }

        // Só conta como pai se ele começou antes do filho — senão é PID reciclado.
        var parent = info.ParentPid is { } ppid ? ProcessInfo.TryRead(ppid) : null;
        result.ParentPid = info.ParentPid;
        if (parent is not null && (parent.StartTime is null || info.StartTime is null || parent.StartTime <= info.StartTime))
        {
            result.ParentProcessPath = parent.ImagePath;
            result.ParentProcessName = parent.ImagePath is null ? null : Path.GetFileName(parent.ImagePath);
        }
        else if (info.ParentPid is not null)
        {
            result.ParentProcessName = "(já encerrado)";
        }

        if (!DomainWhitelistStore.IsCodeHost(processName)) return result;

        // Nunca logar/enviar a linha de comando inteira: o Minecraft passa --accessToken nela.
        if (info.CommandLine is null)
        {
            result.Note = "Não foi possível ler a linha de comando.";
            return result;
        }

        var targets = ExtractScanTargets(processName, SplitArgs(info.CommandLine));
        result.ScanTargets = targets.Paths.Concat(targets.Inline.Select(i => i.Source)).ToArray();

        var findings = new List<FileFindingPayload>();
        var scanned = 0;
        foreach (var file in EnumerateFiles(targets.Paths))
        {
            scanned++;
            if (ScanFileCached(file) is { } finding) findings.Add(finding);
        }
        foreach (var (source, text) in targets.Inline)
        {
            scanned++;
            var hits = FindHits(text, source);
            if (hits.Count > 0) findings.Add(new FileFindingPayload { Path = source, Indicators = hits.ToArray() });
        }

        result.FilesScanned = scanned;
        result.Findings = findings.ToArray();
        return result;
    }

    private void LogInvestigation(InvestigationPayload r)
    {
        var signature = r.ProcessSigned switch
        {
            true => $"válida ({r.ProcessSigner})",
            false => r.ProcessSigner is null ? "sem assinatura" : $"INVÁLIDA ({r.ProcessSigner})",
            null => "?",
        };
        _logger.LogInformation(
            "Investigação do bloqueio {Process} (pid={Pid}) → {Domain}: exe={Path} | sha256={Sha256} | assinatura={Signature} | iniciado={Start} | pai={ParentName} (pid={ParentPid}, {ParentPath}){Note}",
            r.ProcessName, r.Pid, r.Domain, r.ProcessPath ?? "?", r.ProcessSha256 ?? "?", signature,
            r.ProcessStartTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "?",
            r.ParentProcessName ?? "?", r.ParentPid?.ToString() ?? "?", r.ParentProcessPath ?? "?",
            r.Note is null ? "" : " | " + r.Note);

        if (!DomainWhitelistStore.IsCodeHost(r.ProcessName) || r.Note is not null) return;

        _logger.LogInformation(
            "Investigação {Process} (pid={Pid}): {Count} arquivo(s) analisados em {Targets}.",
            r.ProcessName, r.Pid, r.FilesScanned, r.ScanTargets.Length == 0 ? "(nenhum alvo reconhecido)" : string.Join("; ", r.ScanTargets));

        if (r.Findings.Length == 0)
        {
            _logger.LogInformation(
                "Investigação {Process} (pid={Pid}) → {Domain}: nenhum indicador de webhook/token encontrado.",
                r.ProcessName, r.Pid, r.Domain);
            return;
        }

        foreach (var f in r.Findings)
        {
            _logger.LogWarning(
                "Origem provável: {Process} (pid={Pid}) → {Domain}: arquivo {File} | mod={ModId} {ModVersion} ({ModName}) | sha256={Sha256} | tamanho={Size} bytes | modificado={Modified}",
                r.ProcessName, r.Pid, r.Domain, f.Path, f.ModId ?? "?", f.ModVersion ?? "", f.ModName ?? "?",
                f.Sha256 ?? "?", f.SizeBytes, f.LastWriteTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "?");
            foreach (var hit in f.Indicators)
                _logger.LogWarning(
                    "    {Label} em {Entry}: {Match}{Decoded}",
                    hit.Label, hit.Entry, hit.Match, hit.Decoded is null ? "" : " → decodificado: " + hit.Decoded);
        }
    }

    public sealed record ScanTargets(List<string> Paths, List<(string Source, string Text)> Inline);

    /// O que o host de código está executando. Java: -jar e pastas de mods (--gameDir do
    /// launcher oficial/Modrinth/CurseForge, ou instância Prism/MultiMC via
    /// -Djava.library.path=<instância>\natives). Scripts: o arquivo do script, ou o
    /// código inline (-c / -e / -Command / -EncodedCommand), que também é varrido.
    // ponytail: launcher/flag fora desses padrões não é investigado; adicionar quando aparecer no log.
    public static ScanTargets ExtractScanTargets(string processName, IReadOnlyList<string> args)
    {
        var paths = new List<string>();
        var inline = new List<(string, string)>();
        var host = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();

        string? Next(int i) => i + 1 < args.Count ? args[i + 1] : null;
        string? FirstPositional(Func<string, bool> isFlag)
        {
            for (var i = 1; i < args.Count; i++) if (!isFlag(args[i])) return args[i];
            return null;
        }

        switch (host)
        {
            case "java" or "javaw":
                for (var i = 0; i < args.Count; i++)
                {
                    var arg = args[i];
                    if (arg == "-jar" && Next(i) is { } jar) paths.Add(jar);
                    else if (arg == "--gameDir" && Next(i) is { } dir) paths.Add(Path.Combine(dir, "mods"));
                    else if (arg.StartsWith("-Djava.library.path=", StringComparison.Ordinal))
                    {
                        var natives = arg["-Djava.library.path=".Length..].Trim('"').TrimEnd('\\', '/');
                        if (!Path.GetFileName(natives).Equals("natives", StringComparison.OrdinalIgnoreCase)) continue;
                        if (Path.GetDirectoryName(natives) is not { } instance) continue;
                        paths.Add(Path.Combine(instance, "minecraft", "mods"));
                        paths.Add(Path.Combine(instance, ".minecraft", "mods"));
                    }
                }
                break;

            case "python" or "pythonw":
                for (var i = 1; i < args.Count; i++)
                {
                    if (args[i] == "-c" && Next(i) is { } code) { inline.Add(("código inline (python -c)", code)); break; }
                    if (args[i] == "-m" && Next(i) is { } module) { inline.Add(($"módulo python -m {module}", "")); break; }
                    if (!args[i].StartsWith('-')) { paths.Add(args[i]); break; }
                }
                break;

            case "node":
                for (var i = 1; i < args.Count; i++)
                {
                    if (args[i] is "-e" or "--eval" or "-p" or "--print" && Next(i) is { } code) { inline.Add(("código inline (node -e)", code)); break; }
                    if (!args[i].StartsWith('-')) { paths.Add(args[i]); break; }
                }
                break;

            case "powershell" or "pwsh":
                for (var i = 1; i < args.Count; i++)
                {
                    var flag = args[i].ToLowerInvariant();
                    if (flag is "-file" or "-f" && Next(i) is { } file) { paths.Add(file); break; }
                    if (flag is "-encodedcommand" or "-enc" or "-e" or "-ec" && Next(i) is { } enc)
                    {
                        try { inline.Add(("comando PowerShell codificado (-EncodedCommand)", Encoding.Unicode.GetString(Convert.FromBase64String(enc)))); }
                        catch (FormatException) { inline.Add(("comando PowerShell codificado (-EncodedCommand)", enc)); }
                        break;
                    }
                    if (flag is "-command" or "-c")
                    {
                        inline.Add(("comando PowerShell (-Command)", string.Join(' ', args.Skip(i + 1))));
                        break;
                    }
                }
                break;

            case "wscript" or "cscript":
                if (FirstPositional(a => a.StartsWith('/')) is { } script) paths.Add(script);
                break;

            case "mshta":
                if (FirstPositional(_ => false) is { } target)
                {
                    if (File.Exists(target)) paths.Add(target);
                    else inline.Add(("alvo do mshta", target)); // URL ou javascript:/vbscript: inline
                }
                break;
        }

        return new ScanTargets(paths, inline);
    }

    private static IEnumerable<string> EnumerateFiles(IEnumerable<string> targets)
    {
        foreach (var target in targets)
        {
            if (Directory.Exists(target))
            {
                foreach (var jar in Directory.EnumerateFiles(target, "*.jar")) yield return jar;
            }
            else if (File.Exists(target))
            {
                yield return target;
            }
        }
    }

    private FileFindingPayload? ScanFileCached(string path)
    {
        var info = new FileInfo(path);
        var key = $"{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        return _fileCache.GetOrAdd(key, _ =>
        {
            try
            {
                return ScanFile(path);
            }
            catch
            {
                return null; // arquivo corrompido/travado — não é prova de nada
            }
        });
    }

    public static FileFindingPayload? ScanFile(string path)
    {
        var info = new FileInfo(path);
        List<IndicatorHitPayload> hits;
        ModMetadata? mod = null;

        if (path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
        {
            using var stream = File.OpenRead(path);
            (hits, mod) = ScanJar(stream);
        }
        else
        {
            if (info.Length > MaxEntryBytes) return null;
            hits = FindHits(File.ReadAllText(path), Path.GetFileName(path));
        }

        if (hits.Count == 0) return null;
        return new FileFindingPayload
        {
            Path = path,
            Sha256 = Sha256(path),
            SizeBytes = info.Length,
            LastWriteTime = info.LastWriteTime,
            ModId = mod?.Id,
            ModName = mod?.Name,
            ModVersion = mod?.Version,
            Indicators = hits.ToArray(),
        };
    }

    public sealed record ModMetadata(string? Id, string? Name, string? Version);

    /// Busca nas strings dos .class (constant pool fica em claro, só comprimido no zip) e
    /// nos recursos, inclusive jar-in-jar. Também lê id/nome/versão do mod pra o usuário
    /// reconhecer qual é.
    // ponytail: análise estática — string criptografada/ofuscada escapa; cobre stealers de copiar-e-colar, que são a maioria.
    public static (List<IndicatorHitPayload> Hits, ModMetadata? Mod) ScanJar(Stream jarStream, string entryPrefix = "", int depth = 0)
    {
        var hits = new List<IndicatorHitPayload>();
        ModMetadata? mod = null;
        using var zip = new ZipArchive(jarStream, ZipArchiveMode.Read);
        foreach (var entry in zip.Entries)
        {
            if (entry.Length > MaxEntryBytes || entry.Length == 0) continue;

            using var buffer = new MemoryStream((int)entry.Length);
            using (var es = entry.Open()) es.CopyTo(buffer);
            var entryName = entryPrefix + entry.FullName;

            if (entry.FullName.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
            {
                if (depth >= 2) continue;
                buffer.Position = 0;
                try { hits.AddRange(ScanJar(buffer, entryName + "!/", depth + 1).Hits); } catch { }
                continue;
            }

            var text = Encoding.Latin1.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
            hits.AddRange(FindHits(text, entryName));
            if (depth == 0) mod = MergeMod(mod, entry.FullName, buffer);
        }

        return (hits
            .DistinctBy(h => (h.Label, h.Entry, h.Match))
            .Take(MaxHitsPerFile)
            .ToList(), mod);
    }

    public static List<IndicatorHitPayload> FindHits(string text, string entry)
    {
        var hits = new List<IndicatorHitPayload>();
        foreach (var indicator in Indicators)
        {
            foreach (Match m in indicator.Pattern.Matches(text))
            {
                var match = ExpandMatch(text, m.Index, m.Length, indicator.Expand).Trim();
                hits.Add(new IndicatorHitPayload
                {
                    Label = indicator.Label,
                    Entry = entry,
                    Match = match,
                    Decoded = indicator.IsBase64 ? TryDecodeBase64(match) : null,
                });
                if (hits.Count >= MaxHitsPerFile) return hits;
            }
        }
        return hits;
    }

    private static string ExpandMatch(string text, int start, int length, Expand expand)
    {
        const int MaxContext = 160;
        var end = start + length;
        if (expand == Expand.UrlLeft)
        {
            // volta pra pegar https:// e subdomínio (canary., ptb.)
            var limit = Math.Max(0, start - 40);
            while (start > limit && (char.IsAsciiLetterOrDigit(text[start - 1]) || text[start - 1] is '.' or ':' or '/' or '-' or '_')) start--;
        }
        else if (expand == Expand.Context)
        {
            var left = Math.Max(0, start - MaxContext);
            var right = Math.Min(text.Length, end + MaxContext);
            while (start > left && text[start - 1] is >= ' ' and <= '~') start--;
            while (end < right && text[end] is >= ' ' and <= '~') end++;
        }

        // Constant pool do .class: 0x01 + tamanho em 2 bytes antes da string. Se o byte
        // baixo do tamanho for imprimível, a expansão o engoliria — descarta.
        if (expand != Expand.None && start >= 2 && text[start - 1] == '\0' && text[start - 2] == '\u0001') start++;
        return text[start..end];
    }

    private static ModMetadata? MergeMod(ModMetadata? current, string entryName, MemoryStream content)
    {
        try
        {
            switch (entryName)
            {
                case "fabric.mod.json":
                case "quilt.mod.json":
                {
                    using var doc = JsonDocument.Parse(content.ToArray(), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                    var root = doc.RootElement;
                    if (root.TryGetProperty("quilt_loader", out var ql)) root = ql;
                    string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                    var name = Str(root, "name") ?? (root.TryGetProperty("metadata", out var md) ? Str(md, "name") : null);
                    return new ModMetadata(Str(root, "id"), name, Str(root, "version"));
                }
                case "META-INF/mods.toml":
                case "META-INF/neoforge.mods.toml":
                {
                    var toml = Encoding.UTF8.GetString(content.ToArray());
                    string? Field(string name) => Regex.Match(toml, name + @"\s*=\s*""([^""]*)""") is { Success: true } m ? m.Groups[1].Value : null;
                    return new ModMetadata(Field("modId"), Field("displayName"), Field("version"));
                }
                case "META-INF/MANIFEST.MF" when current is null:
                {
                    var manifest = Encoding.UTF8.GetString(content.ToArray());
                    string? Field(string name) => Regex.Match(manifest, "^" + name + @":\s*(.+?)\r?$", RegexOptions.Multiline) is { Success: true } m ? m.Groups[1].Value : null;
                    var title = Field("Implementation-Title") ?? Field("Main-Class");
                    return title is null ? null : new ModMetadata(null, title, Field("Implementation-Version"));
                }
            }
        }
        catch
        {
            // metadado malformado não impede a varredura
        }
        return current;
    }

    private static string? TryDecodeBase64(string s)
    {
        s = s.TrimEnd('=');
        for (var cut = 0; cut < 4 && s.Length - cut > 0; cut++)
        {
            var candidate = s[..(s.Length - cut)];
            candidate = candidate.PadRight((candidate.Length + 3) / 4 * 4, '=');
            try { return Encoding.UTF8.GetString(Convert.FromBase64String(candidate)); }
            catch (FormatException) { }
        }
        return null;
    }

    private static string Base64Prefix(string s)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        return Regex.Escape(Convert.ToBase64String(bytes, 0, bytes.Length / 3 * 3));
    }

    private string? Sha256Cached(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return _hashCache.GetOrAdd($"{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}", _ => Sha256(path));
        }
        catch
        {
            return null;
        }
    }

    private static string? Sha256(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch
        {
            return null; // sem assinatura embutida (ou só assinado por catálogo do Windows)
        }
    }

    private static string[] SplitArgs(string commandLine)
    {
        var argv = CommandLineToArgvW(commandLine, out var argc);
        if (argv == IntPtr.Zero) return Array.Empty<string>();
        try
        {
            var args = new string[argc];
            for (var i = 0; i < argc; i++)
                args[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size))!;
            return args;
        }
        finally
        {
            LocalFree(argv);
        }
    }

    private sealed record ProcessInfo(string? ImagePath, DateTimeOffset? StartTime, int? ParentPid, string? CommandLine)
    {
        public static ProcessInfo? TryRead(int pid)
        {
            var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (handle == IntPtr.Zero) return null;
            try
            {
                return new ProcessInfo(ReadImagePath(handle), ReadStartTime(handle), ReadParentPid(handle), ReadCommandLine(handle));
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private static string? ReadImagePath(IntPtr handle)
        {
            var size = 32768;
            var sb = new StringBuilder(size);
            return QueryFullProcessImageNameW(handle, 0, sb, ref size) ? sb.ToString() : null;
        }

        private static DateTimeOffset? ReadStartTime(IntPtr handle)
            => GetProcessTimes(handle, out var creation, out _, out _, out _) ? DateTimeOffset.FromFileTime(creation) : null;

        private static int? ReadParentPid(IntPtr handle)
        {
            var info = new IntPtr[6]; // PROCESS_BASIC_INFORMATION: 6 campos do tamanho de ponteiro
            var size = IntPtr.Size * info.Length;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (NtQueryInformationProcess(handle, ProcessBasicInformation, buffer, size, out _) != 0) return null;
                return (int)Marshal.ReadIntPtr(buffer, IntPtr.Size * 5); // InheritedFromUniqueProcessId
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string? ReadCommandLine(IntPtr handle)
        {
            NtQueryInformationProcess(handle, ProcessCommandLineInformation, IntPtr.Zero, 0, out var size);
            if (size <= 0) return null;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (NtQueryInformationProcess(handle, ProcessCommandLineInformation, buffer, size, out _) != 0) return null;
                var length = (ushort)Marshal.ReadInt16(buffer); // UNICODE_STRING.Length, em bytes
                var text = Marshal.ReadIntPtr(buffer, IntPtr.Size); // UNICODE_STRING.Buffer
                return Marshal.PtrToStringUni(text, length / 2);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int ProcessBasicInformation = 0;
    private const int ProcessCommandLineInformation = 60;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr info, int infoLength, out int returnLength);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argc);
}
