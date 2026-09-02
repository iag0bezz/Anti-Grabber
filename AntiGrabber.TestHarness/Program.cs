using System.Text;
using AntiGrabber.Shared;

const string SyntheticPayload = "TEST_PAYLOAD_NAO_E_TOKEN_REAL|";

var scenarios = new Dictionary<string, ScenarioDefinition>(StringComparer.OrdinalIgnoreCase)
{
    ["discord-webhook"] = new("discord", "Discord", DefaultTargetUrl: null),
    ["steam-exfil"] = new("steam", "Steam", DefaultTargetUrl: "https://steamcommunity.com/"),
};

var options = ParseArgs(args);
if (!options.TestMode)
{
    Console.Error.WriteLine("Recusado: TestHarness só roda com --test-mode.");
    Console.Error.WriteLine("Uso: AntiGrabber.TestHarness --test-mode --scenario=<cenario> [--webhook-url=<url-de-teste>]");
    Console.Error.WriteLine($"Cenários disponíveis: {string.Join(", ", scenarios.Keys)}");
    return 2;
}

if (!scenarios.TryGetValue(options.Scenario, out var scenario))
{
    Console.Error.WriteLine($"Cenário desconhecido: '{options.Scenario}'. Disponíveis: {string.Join(", ", scenarios.Keys)}");
    return 2;
}

var targetUrl = options.WebhookUrl
    ?? Environment.GetEnvironmentVariable("ANTIGRABBER_TEST_WEBHOOK_URL")
    ?? scenario.DefaultTargetUrl;

if (string.IsNullOrWhiteSpace(targetUrl))
{
    Console.Error.WriteLine(
        "Recusado: nenhum --webhook-url informado nem ANTIGRABBER_TEST_WEBHOOK_URL definido, " +
        $"e o cenário '{options.Scenario}' não tem destino público padrão. " +
        "Use um webhook de teste seu — nunca um webhook de terceiros embutido no repositório.");
    return 2;
}

Console.WriteLine($"=== AntiGrabber TestHarness — cenário {options.Scenario} ({scenario.DisplayName}) ===");

TouchSensitiveFile(scenario.AppId, scenario.DisplayName);

Console.WriteLine($"Enviando payload sintético para {targetUrl} ...");
var blocked = await TrySendPayloadAsync(targetUrl, SyntheticPayload);

Console.WriteLine(blocked
    ? "PASS — conexão foi bloqueada pelo AntiGrabberService."
    : "FAIL — conexão completou (a proteção não interceptou a tentativa).");

return blocked ? 0 : 1;

static void TouchSensitiveFile(string appId, string displayName)
{
    var locator = new UnifiedAppLocator();
    var app = locator.DetectAll().FirstOrDefault(a => a.AppId == appId);
    if (app is null)
    {
        Console.WriteLine($"{displayName} não encontrado nesta máquina — pulando etapa de acesso a arquivo (só testa a rede).");
        return;
    }

    foreach (var dir in app.SensitiveDirectories)
    {
        var existingDir = Directory.Exists(dir) ? dir : Path.GetDirectoryName(dir);
        if (existingDir is null || !Directory.Exists(existingDir)) continue;

        var file = Directory.EnumerateFiles(existingDir).FirstOrDefault();
        if (file is null) continue;

        try
        {
            using var stream = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            Console.WriteLine($"Arquivo sensível tocado (metadados apenas): {Path.GetFileName(file)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Não foi possível tocar {Path.GetFileName(file)}: {ex.Message}");
        }
        return;
    }

    Console.WriteLine($"Nenhum arquivo sensível de {displayName} encontrado pra tocar — só testa a rede.");
}

static async Task<bool> TrySendPayloadAsync(string url, string payload)
{
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
    using var content = new StringContent(payload, Encoding.UTF8, "text/plain");

    try
    {
        using var response = await http.PostAsync(url, content);
        return false;
    }
    catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
    {
        Console.WriteLine($"Conexão não completou ({ex.GetType().Name}) — indicativo de bloqueio.");
        return true;
    }
}

static TestHarnessOptions ParseArgs(string[] args)
{
    var testMode = args.Contains("--test-mode");
    var scenario = args.FirstOrDefault(a => a.StartsWith("--scenario="))?["--scenario=".Length..] ?? "";
    var webhookUrl = args.FirstOrDefault(a => a.StartsWith("--webhook-url="))?["--webhook-url=".Length..];
    return new TestHarnessOptions(testMode, scenario, webhookUrl);
}

sealed record TestHarnessOptions(bool TestMode, string Scenario, string? WebhookUrl);

sealed record ScenarioDefinition(string AppId, string DisplayName, string? DefaultTargetUrl);
