using System.Text;
using AntiGrabber.Service.Network;
using AntiGrabber.Shared;

const string SyntheticPayload = "TEST_PAYLOAD_NAO_E_TOKEN_REAL|";
const string TlsParserSelfTestScenario = "tls-parser-selftest";

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
    Console.Error.WriteLine($"Cenários disponíveis: {string.Join(", ", scenarios.Keys)}, {TlsParserSelfTestScenario} (sem rede)");
    return 2;
}

if (string.Equals(options.Scenario, TlsParserSelfTestScenario, StringComparison.OrdinalIgnoreCase))
{
    try
    {
        return RunTlsParserSelfTest();
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
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

// Self-check puro do TlsSniParser — sem rede, sem WinDivert, sem privilégio elevado.
// Roda em qualquer máquina/CI. Único jeito de saber que a lógica de parsing de
// ClientHello (crítica pra decisão de bloqueio) não quebrou numa mudança futura.
static int RunTlsParserSelfTest()
{
    var withSni = BuildClientHello("example.com");
    var status = TlsSniParser.TryExtractSni(withSni, out var sni);
    Assert(status == ClientHelloParseStatus.Complete, $"ClientHello completo deveria dar Complete, deu {status}");
    Assert(sni == "example.com", $"SNI esperado 'example.com', veio '{sni}'");

    var truncated = withSni[..(withSni.Length - 10)];
    var truncatedStatus = TlsSniParser.TryExtractSni(truncated, out _);
    Assert(truncatedStatus == ClientHelloParseStatus.Incomplete,
        $"ClientHello cortado (simula fragmentação TCP) deveria dar Incomplete, deu {truncatedStatus}");

    var notHandshake = new byte[] { 0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5 }; // application data, não handshake
    var notHandshakeStatus = TlsSniParser.TryExtractSni(notHandshake, out _);
    Assert(notHandshakeStatus == ClientHelloParseStatus.Invalid,
        $"pacote que não é handshake TLS deveria dar Invalid, deu {notHandshakeStatus}");

    var withoutSni = BuildClientHello(sniHost: null);
    var withoutSniStatus = TlsSniParser.TryExtractSni(withoutSni, out var sniAbsent);
    Assert(withoutSniStatus == ClientHelloParseStatus.Complete && sniAbsent is null,
        $"ClientHello sem extensão server_name deveria dar Complete com sni nulo, deu {withoutSniStatus}/{sniAbsent}");

    Console.WriteLine("PASS — TlsSniParser: completo, fragmentado, inválido e sem-SNI, 4/4 ok.");
    return 0;
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException("FAIL — " + message);
}

// Monta um ClientHello TLS mínimo (1 record) só com os campos que o parser precisa
// enxergar. Não é criptograficamente válido nem completo (sem key_share etc.) —
// não precisa ser, é só entrada estrutural pro parser de SNI.
static byte[] BuildClientHello(string? sniHost)
{
    var extensions = new List<byte>();
    if (sniHost is not null)
    {
        var hostBytes = Encoding.ASCII.GetBytes(sniHost);
        var serverNameEntry = new List<byte> { 0x00 }; // name_type = host_name
        serverNameEntry.AddRange(BigEndian16((ushort)hostBytes.Length));
        serverNameEntry.AddRange(hostBytes);

        var serverNameList = new List<byte>();
        serverNameList.AddRange(BigEndian16((ushort)serverNameEntry.Count));
        serverNameList.AddRange(serverNameEntry);

        extensions.AddRange(BigEndian16(0x0000)); // extension type: server_name
        extensions.AddRange(BigEndian16((ushort)serverNameList.Count));
        extensions.AddRange(serverNameList);
    }

    var body = new List<byte>();
    body.AddRange(BigEndian16(0x0303)); // client_version (TLS 1.2 no wire, real version vem em extension)
    body.AddRange(new byte[32]); // random
    body.Add(0x00); // session_id length = 0
    body.AddRange(BigEndian16(0x0002)); // cipher_suites length
    body.AddRange(BigEndian16(0x1301)); // TLS_AES_128_GCM_SHA256
    body.Add(0x01); // compression_methods length
    body.Add(0x00); // null
    body.AddRange(BigEndian16((ushort)extensions.Count));
    body.AddRange(extensions);

    var handshake = new List<byte> { 0x01 }; // msg_type: client_hello
    handshake.AddRange(BigEndian24(body.Count));
    handshake.AddRange(body);

    var record = new List<byte> { 0x16 }; // content_type: handshake
    record.AddRange(BigEndian16(0x0301)); // record version
    record.AddRange(BigEndian16((ushort)handshake.Count));
    record.AddRange(handshake);

    return record.ToArray();
}

static byte[] BigEndian16(ushort value) => new byte[] { (byte)(value >> 8), (byte)value };
static byte[] BigEndian24(int value) => new byte[] { (byte)(value >> 16), (byte)(value >> 8), (byte)value };

sealed record TestHarnessOptions(bool TestMode, string Scenario, string? WebhookUrl);

sealed record ScenarioDefinition(string AppId, string DisplayName, string? DefaultTargetUrl);
