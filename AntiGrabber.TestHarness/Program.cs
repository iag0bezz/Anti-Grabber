using System.Net;
using System.Net.Sockets;
using System.Text;
using AntiGrabber.Service.Network;
using AntiGrabber.Shared;
using WindivertDotnet;

const string SyntheticPayload = "TEST_PAYLOAD_NAO_E_TOKEN_REAL|";
const string TlsParserSelfTestScenario = "tls-parser-selftest";
const string ReassemblySelfTestScenario = "tls-reassembly-selftest";
const string QuicCryptoSelfTestScenario = "quic-crypto-selftest";
const string QuicHeaderSelfTestScenario = "quic-header-selftest";

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
    Console.Error.WriteLine($"Cenários disponíveis: {string.Join(", ", scenarios.Keys)}, {TlsParserSelfTestScenario}, {ReassemblySelfTestScenario}, {QuicCryptoSelfTestScenario}, {QuicHeaderSelfTestScenario} (sem rede)");
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

if (string.Equals(options.Scenario, ReassemblySelfTestScenario, StringComparison.OrdinalIgnoreCase))
{
    try
    {
        return await RunReassemblySelfTestAsync();
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

if (string.Equals(options.Scenario, QuicCryptoSelfTestScenario, StringComparison.OrdinalIgnoreCase))
{
    try
    {
        return RunQuicCryptoSelfTest();
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

if (string.Equals(options.Scenario, QuicHeaderSelfTestScenario, StringComparison.OrdinalIgnoreCase))
{
    try
    {
        return RunQuicHeaderSelfTest();
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

// Self-check do ClientHelloReassembler — sem rede, sem driver WinDivert, sem privilégio
// elevado. Feed() nunca reabre os pacotes que recebe (só clona/guarda pra reenviar depois),
// então um WinDivertPacket/WinDivertAddress vazio serve de "envelope" de teste — os bytes
// de TLS reais viajam pelo parâmetro payload, não pelo conteúdo do pacote.
static async Task<int> RunReassemblySelfTestAsync()
{
    var flowA = new TcpFlowKey(IPAddress.Parse("10.0.0.1"), 51000, IPAddress.Parse("93.184.216.34"), 443);
    var flowB = new TcpFlowKey(IPAddress.Parse("10.0.0.1"), 51001, IPAddress.Parse("93.184.216.34"), 443);

    // Caso 1: ClientHello partido em 2 segmentos TCP chega completo e correto.
    using (var reassembler = new ClientHelloReassembler())
    {
        var fullHello = BuildClientHello("example.com");
        var half = fullHello.Length / 2;
        var chunk1 = fullHello[..half];
        var chunk2 = fullHello[half..];

        var firstStatus = TlsSniParser.TryExtractSni(chunk1, out _);
        Assert(firstStatus == ClientHelloParseStatus.Incomplete,
            $"primeira metade do ClientHello deveria dar Incomplete no parser cru, deu {firstStatus}");

        using var p1 = DummyPacket();
        using var a1 = new WinDivertAddress();
        var r1 = reassembler.Feed(flowA, seq: 1000, chunk1, 51000, AddressFamily.InterNetwork, p1, a1);
        Assert(r1.Status == ReassemblyStatus.Buffering, $"1º fragmento deveria dar Buffering, deu {r1.Status}");
        Assert(reassembler.IsTracking(flowA), "fluxo deveria estar rastreado após 1º fragmento");

        using var p2 = DummyPacket();
        using var a2 = new WinDivertAddress();
        var r2 = reassembler.Feed(flowA, seq: (uint)(1000 + chunk1.Length), chunk2, 51000, AddressFamily.InterNetwork, p2, a2);
        Assert(r2.Status == ReassemblyStatus.Ready, $"2º fragmento deveria completar o ClientHello (Ready), deu {r2.Status}");
        Assert(r2.Sni == "example.com", $"SNI reconstruído esperado 'example.com', veio '{r2.Sni}'");
        Assert(r2.Flush is { Count: 2 }, $"Flush deveria conter os 2 fragmentos originais, veio {r2.Flush?.Count ?? -1}");
        Assert(!reassembler.IsTracking(flowA), "fluxo deveria ter sido removido do rastreamento após completar");
        DisposeFlush(r2.Flush);

        Console.WriteLine("PASS — reassembly: ClientHello em 2 segmentos reconstruído com SNI correto.");
    }

    // Caso 2: primeiro fragmento fica incompleto (só 4 bytes, falta o record header
    // inteiro) e nunca é alcançado por nenhum fragmento seguinte — todos chegam depois
    // de um buraco de sequence number permanente. TotalBytes cresce só com esse lixo
    // não-contíguo até estourar o cap — precisa desistir (fail-open), não bufferizar
    // pra sempre.
    using (var reassembler = new ClientHelloReassembler())
    {
        using var p0 = DummyPacket();
        using var a0 = new WinDivertAddress();
        var first = reassembler.Feed(flowB, seq: 5000, new byte[] { 0x16, 0x03, 0x01, 0x00 }, 51001, AddressFamily.InterNetwork, p0, a0);
        Assert(first.Status == ReassemblyStatus.Buffering,
            $"fragmento de 4 bytes (sem record header completo) deveria dar Buffering, deu {first.Status}");

        var last = first;
        var gapSeq = 90_000u; // bem longe de 5004 (próximo esperado) — buraco nunca fecha
        var totalSent = 4;
        while (totalSent <= 32 * 1024) // mesmo cap do reassembler (32KB) — precisa estourar
        {
            using var p = DummyPacket();
            using var a = new WinDivertAddress();
            var chunk = new byte[2000];
            last = reassembler.Feed(flowB, gapSeq, chunk, 51001, AddressFamily.InterNetwork, p, a);
            gapSeq += (uint)chunk.Length;
            totalSent += chunk.Length;

            if (last.Status != ReassemblyStatus.Buffering) break;
        }

        Assert(last.Status == ReassemblyStatus.GiveUp,
            $"fluxo que estoura o cap de bytes deveria desistir (GiveUp/fail-open), deu {last.Status}");
        Assert(last.Flush is { Count: > 0 }, "GiveUp deveria devolver os fragmentos bufferizados pra reenviar");
        DisposeFlush(last.Flush);

        Console.WriteLine("PASS — reassembly: fluxo com buraco permanente estoura o cap e libera o tráfego (fail-open).");
    }

    // Caso 3: fluxo parado (nenhum fragmento novo) precisa ser varrido por timeout e
    // liberado — senão fica bufferizado pra sempre, vazando memória e travando a conexão.
    using (var reassembler = new ClientHelloReassembler())
    {
        using var p1 = DummyPacket();
        using var a1 = new WinDivertAddress();
        var stuck = reassembler.Feed(flowA, seq: 9000, new byte[] { 0x16, 0x03, 0x01, 0x00, 0x40 }, 51000, AddressFamily.InterNetwork, p1, a1);
        Assert(stuck.Status == ReassemblyStatus.Buffering, "fragmento inicial isolado deveria ficar bufferizado");

        await Task.Delay(900); // > IdleTimeout (750ms) do reassembler

        using var p2 = DummyPacket();
        using var a2 = new WinDivertAddress();
        var other = reassembler.Feed(flowB, seq: 1, new byte[] { 0x17, 0x03, 0x03, 0x00, 0x01, 0x00 }, 51001, AddressFamily.InterNetwork, p2, a2);

        Assert(other.ExpiredFlows is { Count: 1 },
            $"o fluxo travado deveria ter sido varrido como expirado, ExpiredFlows={other.ExpiredFlows?.Count ?? -1}");
        Assert(!reassembler.IsTracking(flowA), "fluxo expirado deveria ter sido removido do rastreamento");
        DisposeFlush(other.ExpiredFlows![0]);
        if (other.Flush is not null) DisposeFlush(other.Flush);

        Console.WriteLine("PASS — reassembly: fluxo parado é varrido por timeout e liberado (sem vazar).");
    }

    return 0;
}

// Self-check do QuicInitialCrypto contra o vetor de teste OFICIAL do RFC 9001
// Apêndice A.2 ("Client Initial") — mesmo DCID, mesmo pacote cifrado real, mesmo
// resultado esperado usado pela suíte de testes da aioquic (implementação QUIC
// de referência). Prova que a derivação HKDF + remoção de header protection +
// AEAD (AES-128-GCM) batem byte a byte com uma implementação real, não só que o
// código compila. pnOffset vem do QuicLongHeaderParser (não é mais fixo à mão) —
// esse teste agora cobre parser + cripto juntos, ponta a ponta.
static int RunQuicCryptoSelfTest()
{
    var dcid = Convert.FromHexString("8394c8f03e515708");
    var encryptedPacket = Rfc9001SampleClientInitialPacket();

    var expectedPayloadPrefix = Convert.FromHexString(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" +
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" +
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" +
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" +
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" +
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100" +
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" +
        "75300901100f088394c8f03e51570806048000ffff");
    var expectedPayload = new byte[expectedPayloadPrefix.Length + 917];
    expectedPayloadPrefix.CopyTo(expectedPayload, 0);

    var parsed = QuicLongHeaderParser.TryParseInitial(encryptedPacket, out var parsedHeader);
    Assert(parsed, "QuicLongHeaderParser deveria reconhecer o pacote do vetor de teste do RFC como Initial válido");
    Assert(parsedHeader.PacketNumberOffset == 18,
        $"pnOffset esperado 18 (mesmo valor usado pelo teste oficial da aioquic), veio {parsedHeader.PacketNumberOffset}");

    var keys = QuicInitialCrypto.DeriveClientInitialKeys(dcid);
    var plaintext = QuicInitialCrypto.TryDecrypt(encryptedPacket, parsedHeader.PacketNumberOffset, keys);

    Assert(plaintext is not null, "TryDecrypt deveria decifrar o pacote do vetor de teste do RFC, veio null");
    Assert(plaintext!.Length == expectedPayload.Length,
        $"tamanho do payload decifrado esperado {expectedPayload.Length}, veio {plaintext.Length}");
    Assert(plaintext.AsSpan().SequenceEqual(expectedPayload),
        "payload decifrado não bate byte a byte com o vetor de teste do RFC 9001 A.2");

    // O ClientHello embutido no frame CRYPTO tem SNI "example.com" — confere que
    // o parser de ClientHello já existente (mesmo usado no caminho TCP) reconhece
    // esse trecho igual reconheceria vindo de TLS puro. Frame CRYPTO aqui: type(1)
    // + offset varint 1 byte (0x00, valor 0) + length varint 2 bytes (0x40f1,
    // valor 241) = 4 bytes de cabeçalho antes da mensagem de handshake real.
    var cryptoFrameHandshake = plaintext.AsSpan(4, expectedPayloadPrefix.Length - 4);
    var withFakeRecordHeader = new byte[5 + cryptoFrameHandshake.Length];
    withFakeRecordHeader[0] = 0x16; withFakeRecordHeader[3] = (byte)(cryptoFrameHandshake.Length >> 8); withFakeRecordHeader[4] = (byte)cryptoFrameHandshake.Length;
    cryptoFrameHandshake.CopyTo(withFakeRecordHeader.AsSpan(5));
    var status = TlsSniParser.TryExtractSni(withFakeRecordHeader, out var sni);
    Assert(status == ClientHelloParseStatus.Complete, $"ClientHello dentro do frame CRYPTO deveria dar Complete, deu {status}");
    Assert(sni == "example.com", $"SNI esperado 'example.com', veio '{sni}'");

    Console.WriteLine("PASS — QuicInitialCrypto: vetor oficial RFC 9001 A.2 decifrado byte a byte, SNI 'example.com' extraído.");
    return 0;
}

static WinDivertPacket DummyPacket()
{
    var p = new WinDivertPacket(1);
    p.Length = 1;
    return p;
}

static void DisposeFlush(List<PendingFragment>? fragments)
{
    if (fragments is null) return;
    foreach (var f in fragments) { f.Packet.Dispose(); f.Address.Dispose(); }
}

// Self-check do QuicLongHeaderParser — mesmo pacote oficial do RFC 9001 A.2.
// Valores esperados calculados à mão a partir do header em texto claro que o
// próprio RFC publica: DCID de 8 bytes (8394c8f03e515708), SCID vazio, token
// vazio, campo Length=1182 (0x449e) e por isso pnOffset=18. Bate exatamente com
// o "encrypted_offset=18" que a suíte de teste da aioquic usa pra decifrar esse
// mesmo pacote.
static int RunQuicHeaderSelfTest()
{
    var packet = Rfc9001SampleClientInitialPacket();

    var ok = QuicLongHeaderParser.TryParseInitial(packet, out var header);
    Assert(ok, "deveria reconhecer o pacote do RFC 9001 A.2 como QUIC Initial válido");
    Assert(string.Equals(Convert.ToHexString(header.DestinationConnectionId), "8394c8f03e515708", StringComparison.OrdinalIgnoreCase),
        $"DCID esperado 8394c8f03e515708, veio {Convert.ToHexString(header.DestinationConnectionId)}");
    Assert(header.SourceConnectionId.Length == 0, $"SCID deveria ser vazio, veio {header.SourceConnectionId.Length} bytes");
    Assert(header.Token.Length == 0, $"Token deveria ser vazio, veio {header.Token.Length} bytes");
    Assert(header.PacketNumberOffset == 18, $"pnOffset esperado 18, veio {header.PacketNumberOffset}");
    Assert(header.TotalPacketLength == 1200,
        $"tamanho total esperado 1200 (Initial packets são preenchidos até esse mínimo), veio {header.TotalPacketLength}");
    Assert(header.TotalPacketLength == packet.Length,
        "Length declarado no header deveria cobrir o pacote inteiro nesse vetor (não há mais pacotes coalescidos depois)");

    // Um pacote qualquer que não é QUIC (ou é QUIC mas não Initial/v1) precisa
    // ser rejeitado sem lançar exceção — é tráfego comum (curto header, versão
    // desconhecida, etc.) que o chamador deve simplesmente liberar.
    var notLongHeader = new byte[] { 0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    Assert(!QuicLongHeaderParser.TryParseInitial(notLongHeader, out _),
        "pacote com header curto (bit 0x80 não setado) não deveria parsear como Initial");

    Console.WriteLine("PASS — QuicLongHeaderParser: DCID/SCID/token/pnOffset/length batem com o vetor oficial RFC 9001 A.2.");
    return 0;
}

// Pacote QUIC Initial real de exemplo, publicado no RFC 9001 Apêndice A.2 —
// mesmo hex usado pela suíte de testes oficial da aioquic (LONG_CLIENT_ENCRYPTED_PACKET).
static byte[] Rfc9001SampleClientInitialPacket() => Convert.FromHexString(
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" +
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" +
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" +
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" +
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" +
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" +
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" +
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" +
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" +
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" +
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" +
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" +
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" +
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" +
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" +
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" +
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" +
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" +
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" +
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" +
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" +
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" +
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" +
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" +
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" +
    "e221af44860018ab0856972e194cd934");

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
