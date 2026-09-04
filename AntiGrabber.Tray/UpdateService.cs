using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace AntiGrabber.Tray;

public sealed record PendingUpdate(string Version, string Notes, string ZipUrl, string ShaUrl);

// Porta o subsistema de auto-update do main.js: checa GitHub Releases, só baixa
// e aplica quando o usuário confirma. HttpClient no lugar de electron.net —
// sem a classe de bug de proxy-hang que motivou usar electron.net em vez de
// node:https no processo principal do Electron; aqui não existe esse problema.
public sealed class UpdateService
{
    private const string GitHubRepo = "iag0bezz/Anti-Grabber";
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly Store _store;
    private readonly Action<string, object?> _send;
    private bool _inProgress;

    public PendingUpdate? Pending { get; private set; }

    public UpdateService(Store store, Action<string, object?> send)
    {
        _store = store;
        _send = send;
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("AntiGrabber-Tray");
    }

    public static string GetAppVersion() =>
        System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

    public async Task CheckAsync()
    {
        try
        {
            var json = await _http.GetStringAsync($"https://api.github.com/repos/{GitHubRepo}/releases/latest");
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var remoteVersion = (root.TryGetProperty("tag_name", out var tag) ? tag.GetString() : null)?.TrimStart('v') ?? "";
            if (remoteVersion.Length == 0) return;

            _store.UpdateSettings(s => s.LastUpdateCheck = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

            if (CompareVersions(remoteVersion, GetAppVersion()) <= 0) return;
            if (_store.GetSettings().SkippedVersion == remoteVersion) return;

            string? zipUrl = null, shaUrl = null;
            if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
            {
                foreach (var asset in assets.EnumerateArray())
                {
                    var name = asset.GetProperty("name").GetString();
                    var url = asset.GetProperty("browser_download_url").GetString();
                    if (name == $"AntiGrabberUpdate-{remoteVersion}.zip") zipUrl = url;
                    else if (name == $"AntiGrabberUpdate-{remoteVersion}.zip.sha256") shaUrl = url;
                }
            }
            if (zipUrl is null || shaUrl is null) return;

            var notes = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            Pending = new PendingUpdate(remoteVersion, notes, zipUrl, shaUrl);
            _send("update-available", new { version = remoteVersion, notes });
        }
        catch
        {
            // offline, GitHub fora do ar, rate limit — nunca vira erro visível pro usuário.
        }
    }

    private static int CompareVersions(string a, string b)
    {
        var pa = a.Split('.');
        var pb = b.Split('.');
        for (var i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            var na = i < pa.Length && int.TryParse(pa[i], out var xa) ? xa : 0;
            var nb = i < pb.Length && int.TryParse(pb[i], out var xb) ? xb : 0;
            if (na != nb) return na - nb;
        }
        return 0;
    }

    public async Task ApplyAsync(string helperScriptPath, string installRoot)
    {
        if (Pending is not { } pending || _inProgress) return;
        _inProgress = true;
        try
        {
            var workDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "AntiGrabber", "updates", pending.Version);
            Directory.CreateDirectory(workDir);
            var zipPath = Path.Combine(workDir, "update.zip");
            var extractDir = Path.Combine(workDir, "extracted");

            _send("update-progress", new { phase = "downloading", percent = 0 });
            await DownloadAsync(pending.ZipUrl, zipPath, percent => _send("update-progress", new { phase = "downloading", percent }));

            _send("update-progress", new { phase = "verifying" });
            var shaText = await _http.GetStringAsync(pending.ShaUrl);
            var expectedHash = shaText.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.ToLowerInvariant() ?? "";
            var actualHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(zipPath))).ToLowerInvariant();
            if (expectedHash.Length == 0 || actualHash != expectedHash) throw new InvalidOperationException("hash-mismatch-zip");

            _send("update-progress", new { phase = "extracting" });
            if (Directory.Exists(extractDir)) Directory.Delete(extractDir, recursive: true);
            ZipFile.ExtractToDirectory(zipPath, extractDir);

            var manifestJson = await File.ReadAllTextAsync(Path.Combine(extractDir, "manifest.json"));
            using (var manifest = JsonDocument.Parse(manifestJson))
            {
                foreach (var f in manifest.RootElement.GetProperty("files").EnumerateArray())
                {
                    var relPath = f.GetProperty("path").GetString()!;
                    var expected = f.GetProperty("sha256").GetString()!.ToLowerInvariant();
                    var actual = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(extractDir, relPath)))).ToLowerInvariant();
                    if (actual != expected) throw new InvalidOperationException($"hash-mismatch-file:{relPath}");
                }
            }

            _send("update-progress", new { phase = "elevating" });
            var ok = await RunElevatedHelperAsync(helperScriptPath, extractDir, installRoot);
            if (!ok) throw new InvalidOperationException("helper-failed");

            _send("update-progress", new { phase = "relaunching" });
            try { Directory.Delete(workDir, recursive: true); } catch { }

            System.Diagnostics.Process.Start(Environment.ProcessPath!);
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            _send("update-progress", new { phase = "error", message = ex.Message });
        }
        finally
        {
            _inProgress = false;
        }
    }

    private async Task DownloadAsync(string url, string destPath, Action<int> onProgress)
    {
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();
        var total = response.Content.Headers.ContentLength ?? 0;
        await using var stream = await response.Content.ReadAsStreamAsync();
        await using var fileStream = File.Create(destPath);

        var buffer = new byte[81920];
        long received = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer)) > 0)
        {
            await fileStream.WriteAsync(buffer.AsMemory(0, read));
            received += read;
            if (total > 0) onProgress((int)(received * 100 / total));
        }
    }

    // Mesmo padrão manual usado várias vezes nesta sessão via PowerShell — só que
    // aqui é nativo: ProcessStartInfo.Verb="runas" já dispara o UAC e devolve o
    // ExitCode direto, sem precisar do truque de gravar o código num arquivo temp
    // que o main.js original precisava (Start-Process -Verb RunAs não devolve
    // ExitCode pro processo pai de outro jeito).
    private static Task<bool> RunElevatedHelperAsync(string scriptPath, string stagingDir, string installDir)
    {
        return Task.Run(() =>
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell",
                    UseShellExecute = true,
                    Verb = "runas",
                };
                psi.ArgumentList.Add("-NoProfile");
                psi.ArgumentList.Add("-ExecutionPolicy");
                psi.ArgumentList.Add("Bypass");
                psi.ArgumentList.Add("-File");
                psi.ArgumentList.Add(scriptPath);
                psi.ArgumentList.Add("-StagingDir");
                psi.ArgumentList.Add(stagingDir);
                psi.ArgumentList.Add("-InstallDir");
                psi.ArgumentList.Add(installDir);

                using var process = System.Diagnostics.Process.Start(psi);
                process?.WaitForExit();
                return process?.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        });
    }
}
