using System.Security.Cryptography;
using System.Text.Json;

namespace AntiGrabber.Tray;

public sealed record PendingUpdate(string Version, string Notes, string SetupUrl, string ShaUrl);

// Checa GitHub Releases, só baixa e aplica quando o usuário confirma. Baixa o
// próprio AntiGrabberSetup.exe (mesmo instalador Inno Setup do release) e roda
// ele elevado em modo silencioso — não existe mais artefato de update separado
// (zip+manifest): instalador e auto-update são o mesmo binário.
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

            string? setupUrl = null, shaUrl = null;
            if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
            {
                foreach (var asset in assets.EnumerateArray())
                {
                    var name = asset.GetProperty("name").GetString();
                    var url = asset.GetProperty("browser_download_url").GetString();
                    if (name == "AntiGrabberSetup.exe") setupUrl = url;
                    else if (name == "AntiGrabberSetup.exe.sha256") shaUrl = url;
                }
            }
            if (setupUrl is null || shaUrl is null) return;

            var notes = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            Pending = new PendingUpdate(remoteVersion, notes, setupUrl, shaUrl);
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

    public async Task ApplyAsync()
    {
        if (Pending is not { } pending || _inProgress) return;
        _inProgress = true;
        try
        {
            var workDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "AntiGrabber", "updates", pending.Version);
            Directory.CreateDirectory(workDir);
            var setupPath = Path.Combine(workDir, "AntiGrabberSetup.exe");

            _send("update-progress", new { phase = "downloading", percent = 0 });
            await DownloadAsync(pending.SetupUrl, setupPath, percent => _send("update-progress", new { phase = "downloading", percent }));

            _send("update-progress", new { phase = "verifying" });
            var shaText = await _http.GetStringAsync(pending.ShaUrl);
            var expectedHash = shaText.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.ToLowerInvariant() ?? "";
            var actualHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(setupPath))).ToLowerInvariant();
            if (expectedHash.Length == 0 || actualHash != expectedHash) throw new InvalidOperationException("hash-mismatch-setup");

            // Instalador roda elevado e silencioso, sobrescreve a instalação atual
            // (mesmo AppId do Inno Setup = update in-place) e relança o Tray sozinho
            // (ver [Run] com Check: WizardSilent no .iss) — inclusive fecha este
            // processo (taskkill no [Code] do .iss antes de copiar arquivos).
            _send("update-progress", new { phase = "installing" });
            var ok = await RunInstallerElevatedAsync(setupPath);
            if (!ok) throw new InvalidOperationException("installer-failed");

            _send("update-progress", new { phase = "relaunching" });
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

    // ProcessStartInfo.Verb="runas" dispara o UAC e devolve o ExitCode direto do
    // instalador Inno Setup. Flags silenciosas: /VERYSILENT sem wizard nem barra
    // de progresso própria (o Tray já mostra o progresso via "update-progress"),
    // /SUPPRESSMSGBOXES evita prompts, /NORESTART não reinicia o Windows.
    private static Task<bool> RunInstallerElevatedAsync(string setupPath)
    {
        return Task.Run(() =>
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = setupPath,
                    UseShellExecute = true,
                    Verb = "runas",
                };
                psi.ArgumentList.Add("/VERYSILENT");
                psi.ArgumentList.Add("/SUPPRESSMSGBOXES");
                psi.ArgumentList.Add("/NORESTART");
                psi.ArgumentList.Add("/SP-");

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
