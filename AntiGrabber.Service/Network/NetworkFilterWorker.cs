using System.Diagnostics;
using System.Net.Sockets;
using AntiGrabber.Service.FileWatch;
using AntiGrabber.Service.Ipc;
using AntiGrabber.Shared;
using Microsoft.Extensions.Options;
using WindivertDotnet;

namespace AntiGrabber.Service.Network;

public sealed class NetworkFilterWorker : BackgroundService
{
    private readonly ILogger<NetworkFilterWorker> _logger;
    private readonly DomainWhitelistStore _whitelist;
    private readonly CorrelationTracker _correlationTracker;
    private readonly IpcServer _ipcServer;
    private readonly BlockStatsTracker _blockStats;
    private readonly ProcessNameCache _processNameCache;
    private readonly BlockInvestigator _blockInvestigator;
    private readonly NetworkFilterOptions _options;
    private readonly ClientHelloReassembler _reassembler = new();
    private readonly QuicClientHelloReassembler _quicReassembler = new();
    // 30s cobre o ciclo de retransmissão do TCP (~21s no Windows) com folga; reuso de
    // porta local efêmera pro mesmo destino dentro disso é improvável.
    private readonly BlockedFlows<TcpFlowKey> _blockedTcp = new(TimeSpan.FromSeconds(30));
    private readonly BlockedFlows<UdpFlowKey> _blockedUdp = new(TimeSpan.FromSeconds(30));

    public NetworkFilterWorker(
        ILogger<NetworkFilterWorker> logger,
        DomainWhitelistStore whitelist,
        CorrelationTracker correlationTracker,
        IpcServer ipcServer,
        BlockStatsTracker blockStats,
        ProcessNameCache processNameCache,
        BlockInvestigator blockInvestigator,
        IOptions<NetworkFilterOptions> options)
    {
        _logger = logger;
        _whitelist = whitelist;
        _correlationTracker = correlationTracker;
        _ipcServer = ipcServer;
        _blockStats = blockStats;
        _processNameCache = processNameCache;
        _blockInvestigator = blockInvestigator;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        WinDivert divert;
        try
        {
            var filter = _options.InspectQuic
                ? "outbound and (tcp.DstPort == 443 or udp.DstPort == 443)"
                : "outbound and tcp.DstPort == 443";
            divert = new WinDivert(filter, WinDivertLayer.Network, 0, WinDivertFlag.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Não foi possível abrir o driver WinDivert. O serviço precisa rodar elevado (LocalSystem) " +
                "e o WinDivert64.sys precisa estar ao lado do executável.");
            return;
        }

        using (divert)
        using (_reassembler)
        using (_quicReassembler)
        {
            using var packet = new WinDivertPacket(ushort.MaxValue);
            using var address = new WinDivertAddress();

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await divert.RecvAsync(packet, address, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Erro recebendo pacote do WinDivert.");
                    continue;
                }

                try
                {
                    await ProcessPacketAsync(divert, packet, address, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Erro processando pacote.");
                }
            }
        }
    }

    private async Task ProcessPacketAsync(WinDivert divert, WinDivertPacket packet, WinDivertAddress address, CancellationToken ct)
    {
        WinDivertParseResult parsed;
        try
        {
            parsed = packet.GetParseResult();
        }
        catch
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        if (parsed.Protocol == ProtocolType.Udp && HasUdpHeader(parsed))
        {
            await ProcessQuicPacketAsync(divert, packet, address, parsed, ct);
            return;
        }

        if (parsed.Protocol != ProtocolType.Tcp || !HasTcpHeader(parsed))
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        var flowKey = GetFlowKey(parsed);

        // Fluxo já bloqueado: descarta tudo (retransmissão, continuação, FIN) antes de
        // qualquer caminho fail-open abaixo.
        if (flowKey is { } blockedKey && _blockedTcp.IsBlocked(blockedKey, DateTime.UtcNow))
            return;

        // Fragmento de continuação de um ClientHello já em reassembly (não começa com
        // 0x16 — é só o meio de um record TLS partido em vários segmentos TCP).
        if (flowKey is { } trackedKey && parsed.DataLength > 0 && _reassembler.IsTracking(trackedKey))
        {
            var result = _reassembler.Feed(
                trackedKey, SeqOf(parsed), parsed.DataSpan,
                SrcPortOf(parsed), FamilyOf(parsed), packet, address);
            await HandleReassemblyResultAsync(divert, trackedKey, result, packet, address, ct);
            return;
        }

        if (parsed.DataLength == 0)
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        var status = TlsSniParser.TryExtractSni(parsed.DataSpan, out var sni);

        if (status == ClientHelloParseStatus.Invalid)
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        if (status == ClientHelloParseStatus.Incomplete)
        {
            if (flowKey is not { } newKey)
            {
                // Sem IPv4/IPv6 reconhecido — não dá pra rastrear por fluxo, desiste.
                await ForwardAsync(divert, packet, address, ct);
                return;
            }

            var result = _reassembler.Feed(
                newKey, SeqOf(parsed), parsed.DataSpan,
                SrcPortOf(parsed), FamilyOf(parsed), packet, address);
            await HandleReassemblyResultAsync(divert, newKey, result, packet, address, ct);
            return;
        }

        // status == Complete — fast path, ClientHello vinha inteiro num pacote só.
        if (sni is null)
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        var allow = await DecideAsync(sni, SrcPortOf(parsed), FamilyOf(parsed), isUdp: false, ct);
        if (allow)
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        if (flowKey is { } key) _blockedTcp.Add(key, DateTime.UtcNow);
        await InjectResetAsync(divert, packet, address, ct);
    }

    /// Caminho QUIC/UDP 443 — só inspeciona o Initial packet do handshake (onde o
    /// ClientHello viaja em claro, ver QuicInitialCrypto). Pacotes de fases seguintes
    /// (Handshake/1-RTT) não dá pra decifrar sem os segredos negociados depois do
    /// Initial, e por isso passam liberados (fail-open) — decisão já foi tomada aqui.
    private async Task ProcessQuicPacketAsync(WinDivert divert, WinDivertPacket packet, WinDivertAddress address, WinDivertParseResult parsed, CancellationToken ct)
    {
        var flowKey = GetUdpFlowKey(parsed);
        if (flowKey is { } blockedKey && _blockedUdp.IsBlocked(blockedKey, DateTime.UtcNow))
            return;

        if (flowKey is not { } key || !QuicLongHeaderParser.TryParseInitial(parsed.DataSpan, out var header))
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        if (header.TotalPacketLength > parsed.DataSpan.Length)
        {
            // Length declarado no header maior que o datagrama recebido — truncado/corrompido.
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        var keys = QuicInitialCrypto.DeriveClientInitialKeys(header.DestinationConnectionId);
        // Só decifra este Initial packet — datagramas QUIC podem coalescer mais de um
        // pacote (ex: Initial + Handshake), e o resto não é nosso pra decifrar aqui.
        var plaintext = QuicInitialCrypto.TryDecrypt(parsed.DataSpan[..header.TotalPacketLength], header.PacketNumberOffset, keys);
        if (plaintext is null)
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        if (!QuicCryptoFrameExtractor.TryExtract(plaintext, out var chunks) || chunks.Count == 0)
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        var result = _quicReassembler.Feed(key, chunks, UdpSrcPortOf(parsed), FamilyOf(parsed), packet, address);
        await HandleQuicReassemblyResultAsync(divert, key, result, ct);
    }

    /// Segmentos parciais do ClientHello seguem pro fio na hora; o reassembler guarda só
    /// a cópia dos bytes. Segurar o 1º segmento travava a conexão: pelo Nagle, o TCP só
    /// manda o 2º segmento (pequeno) depois do ACK do 1º — que nunca vinha — até o fluxo
    /// expirar e ser liberado sem decisão. Agora só o segmento que COMPLETA o ClientHello
    /// espera a decisão: se bloquear, ele cai, o servidor nunca tem o ClientHello inteiro
    /// (sem handshake, sem dado), e o resto do fluxo cai via _blockedTcp.
    /// ponytail: segmento fora de ordem (o que completa chega antes do 1º) ainda vaza —
    /// raro no envio local; ler SNI parcial do 1º segmento resolve se aparecer.
    private async Task HandleReassemblyResultAsync(WinDivert divert, TcpFlowKey key, ReassemblyResult result,
        WinDivertPacket current, WinDivertAddress currentAddress, CancellationToken ct)
    {
        switch (result.Status)
        {
            case ReassemblyStatus.Buffering:
                await ForwardAsync(divert, current, currentAddress, ct);
                break;

            case ReassemblyStatus.GiveUp:
                LogFailOpen("reassembly TCP desistiu", key.DstAddr, key.SrcPort);
                await ForwardAsync(divert, current, currentAddress, ct);
                await FlushAsync(divert, result.Flush!, forward: false, ct); // os outros já foram
                break;

            case ReassemblyStatus.Ready:
                var allow = await DecideAsync(result.Sni!, result.LocalPort, result.Family, isUdp: false, ct);
                if (allow)
                {
                    await ForwardAsync(divert, current, currentAddress, ct);
                }
                else
                {
                    _blockedTcp.Add(key, DateTime.UtcNow);
                    await InjectResetAsync(divert, current, currentAddress, ct);
                }
                await FlushAsync(divert, result.Flush!, forward: false, ct);
                break;
        }

        // Fluxo que nunca completou: os segmentos já foram repassados, só libera a memória.
        if (result.ExpiredFlows is { Count: > 0 } expired)
            foreach (var flow in expired)
                await FlushAsync(divert, flow, forward: false, ct);
    }

    private async Task HandleQuicReassemblyResultAsync(WinDivert divert, UdpFlowKey key, ReassemblyResult result, CancellationToken ct)
    {
        switch (result.Status)
        {
            case ReassemblyStatus.Buffering:
                break;

            case ReassemblyStatus.GiveUp:
                LogFailOpen("reassembly QUIC desistiu", key.DstAddr, key.SrcPort);
                await FlushAsync(divert, result.Flush!, forward: true, ct);
                break;

            case ReassemblyStatus.Ready:
                var allow = await DecideAsync(result.Sni!, result.LocalPort, result.Family, isUdp: true, ct);
                if (!allow) _blockedUdp.Add(key, DateTime.UtcNow);
                await FlushAsync(divert, result.Flush!, forward: allow, ct);
                break;
        }

        if (result.ExpiredFlows is { Count: > 0 } expired)
        {
            _logger.LogInformation("Fail-open: {Count} fluxo(s) com ClientHello incompleto expiraram e foram liberados sem decisão.", expired.Count);
            foreach (var flow in expired)
                await FlushAsync(divert, flow, forward: true, ct);
        }
    }

    private async Task<bool> DecideAsync(string sni, ushort localPort, AddressFamily family, bool isUdp, CancellationToken ct)
    {
        var sensitive = _whitelist.IsSensitiveDomain(sni);
        if (!sensitive && !_correlationTracker.AnyRecentAccountRead) return true;

        var pid = isUdp
            ? UdpProcessResolver.ResolvePidByLocalPort(localPort, family)
            : TcpProcessResolver.ResolvePidByLocalPort(localPort, family);

        var processName = TryGetProcessName(pid);
        if (processName is not null && pid is not null)
            _processNameCache.Record(pid.Value, sni, processName);
        else if (pid is not null)
            processName = _processNameCache.TryGetRecent(pid.Value, sni);

        // Processo de fora que acabou de ler arquivo de conta (token do Minecraft etc.) não
        // fala com NINGUÉM na janela — stealer manda pra servidor próprio, não só pros
        // domínios sensíveis — e nenhuma liberação vale por cima disso.
        var accountRead = pid is not null ? _correlationTracker.TryGetRecentAccountRead(pid.Value) : null;
        if (accountRead is null && !sensitive) return true;

        if (accountRead is null && processName is not null && _whitelist.IsAllowed(sni, processName))
            return true;

        // Host de código (javaw, python...) liberado pelo usuário pra ESTE conjunto de
        // mods/scripts. Nunca vale se o processo acabou de ler arquivo sensível ou se a
        // investigação achou indicador de stealer.
        if (accountRead is null && processName is not null && pid is not null
            && DomainWhitelistStore.IsCodeHost(processName)
            && _whitelist.HasFingerprintRule(sni, processName)
            && !_correlationTracker.HasRecentFileAccess(pid.Value)
            && (_blockInvestigator.TryGetCached(pid.Value)?.Findings.Length ?? 0) == 0)
        {
            var fingerprint = _blockInvestigator.TryGetHostFingerprint(pid.Value, processName, out var pending);
            if (fingerprint is not null && _whitelist.IsAllowed(sni, processName, fingerprint))
                return true;
            if (pending)
            {
                // Conjunto liberado pelo usuário ainda sendo conferido (hash dos jars): segura
                // sem alarde — o mod tenta de novo e passa assim que o hash bater.
                _logger.LogInformation(
                    "Aguardando conferência do conjunto de mods/scripts de {Process} (pid={Pid}) antes de liberar {Domain}.",
                    processName, pid, sni);
                return false;
            }
        }

        var correlatedFileAccess = accountRead is not null || (pid is not null && _correlationTracker.HasRecentFileAccess(pid.Value));
        var correlatedFilePath = accountRead?.Path ?? (pid is not null ? _correlationTracker.TryGetRecentFilePath(pid.Value) : null);
        _blockStats.RecordBlock();

        _logger.LogWarning(
            "Bloqueado: {Process} (pid={Pid}) tentou conectar em {Domain}. Acesso a arquivo sensível recente: {Correlated}",
            processName ?? "desconhecido", pid?.ToString() ?? "?", sni, correlatedFileAccess);

        if (pid is not null)
            _blockInvestigator.InvestigateBlock(pid.Value, processName ?? "desconhecido", sni);

        await _ipcServer.PublishAsync(new IpcEnvelope
        {
            Type = IpcMessageType.BlockEvent,
            BlockEvent = new BlockEventPayload
            {
                Timestamp = DateTimeOffset.UtcNow,
                ProcessName = processName ?? "processo desconhecido",
                Domain = sni,
                CorrelatedFileAccess = correlatedFileAccess,
                Pid = pid,
                LocalPort = localPort,
                CorrelatedFilePath = correlatedFilePath,
                Protocol = isUdp ? "QUIC" : "TCP",
                Investigation = pid is not null ? _blockInvestigator.TryGetCached(pid.Value) : null,
                PlainLanguageMessage = accountRead is { } read
                    ? $"Bloqueamos um possível roubo de conta: {processName ?? "um programa"} leu seus dados de login do {read.App} e tentou enviar para {sni}."
                    : correlatedFileAccess
                    ?$"Bloqueamos uma tentativa de roubo: {processName ?? "um programa"} tentou enviar dados para {sni} logo após acessar seus arquivos."
                    : $"Bloqueamos uma conexão suspeita: {processName ?? "um programa"} tentou falar com {sni} sem autorização.",
            },
        });
        await _ipcServer.PublishStatusAsync("recentBlock");

        return false;
    }

    // Só os caminhos fail-open raros (desistência/expiração) — Invalid acontece em todo
    // pacote HTTPS que não é ClientHello e afogaria o log.
    private void LogFailOpen(string reason, System.Net.IPAddress dst, ushort localPort) =>
        _logger.LogInformation("Fail-open: {Reason} (destino {Dst}, porta local {Port}) — tráfego liberado sem decisão.", reason, dst, localPort);

    /// Derruba a conexão do lado do app na hora, em vez de deixar o TCP retransmitir até
    /// dar timeout: RST "vindo do servidor", montado a partir do pacote bloqueado e
    /// injetado como inbound. Melhor esforço — o descarte via _blockedTcp já garante o
    /// bloqueio mesmo se o RST falhar.
    private async Task InjectResetAsync(WinDivert divert, WinDivertPacket blocked, WinDivertAddress blockedAddress, CancellationToken ct)
    {
        try
        {
            using var rst = blocked.Clone();
            using var addr = blockedAddress.Clone();
            if (!TurnIntoInboundReset(rst)) return;
            addr.Flags &= ~WinDivertAddressFlag.Outbound;
            rst.CalcChecksums(addr, default);
            await divert.SendAsync(rst, addr, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro injetando RST no fluxo bloqueado.");
        }
    }

    private static unsafe bool TurnIntoInboundReset(WinDivertPacket packet)
    {
        var parsed = packet.GetParseResult();
        var tcp = parsed.TcpHeader;
        if (tcp == null) return false;

        var seq = tcp->SeqNum;
        var ack = tcp->AckNum;
        var dataLength = parsed.DataLength;

        packet.ReverseEndPoint();
        tcp->SeqNum = ack;                          // o que o "servidor" mandaria a seguir
        tcp->AckNum = seq + (uint)dataLength;       // confirma o ClientHello inteiro
        tcp->Syn = false;
        tcp->Fin = false;
        tcp->Psh = false;
        tcp->Urg = false;
        tcp->Rst = true;
        tcp->Ack = true;
        tcp->Window = 0;

        packet.Length -= dataLength;                // RST sem payload
        packet.ApplyLengthToHeaders();
        return true;
    }

    private async Task ForwardAsync(WinDivert divert, WinDivertPacket packet, WinDivertAddress address, CancellationToken ct)
    {
        try { await divert.SendAsync(packet, address, ct); }
        catch (Exception ex) { _logger.LogWarning(ex, "Erro reenviando pacote."); }
    }

    private async Task FlushAsync(WinDivert divert, List<PendingFragment> fragments, bool forward, CancellationToken ct)
    {
        foreach (var frag in fragments)
        {
            try
            {
                if (forward) await divert.SendAsync(frag.Packet, frag.Address, ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Erro reenviando fragmento bufferizado.");
            }
            finally
            {
                frag.Packet.Dispose();
                frag.Address.Dispose();
            }
        }
    }

    private static unsafe bool HasTcpHeader(WinDivertParseResult parsed) => parsed.TcpHeader != null;

    private static unsafe uint SeqOf(WinDivertParseResult parsed) => parsed.TcpHeader->SeqNum;

    private static unsafe ushort SrcPortOf(WinDivertParseResult parsed) => parsed.TcpHeader->SrcPort;

    private static unsafe TcpFlowKey? GetFlowKey(WinDivertParseResult parsed)
    {
        if (parsed.TcpHeader == null) return null;
        if (parsed.IPV4Header != null)
            return new TcpFlowKey(parsed.IPV4Header->SrcAddr, parsed.TcpHeader->SrcPort, parsed.IPV4Header->DstAddr, parsed.TcpHeader->DstPort);
        if (parsed.IPV6Header != null)
            return new TcpFlowKey(parsed.IPV6Header->SrcAddr, parsed.TcpHeader->SrcPort, parsed.IPV6Header->DstAddr, parsed.TcpHeader->DstPort);
        return null;
    }

    private static unsafe bool HasUdpHeader(WinDivertParseResult parsed) => parsed.UdpHeader != null;

    private static unsafe ushort UdpSrcPortOf(WinDivertParseResult parsed) => parsed.UdpHeader->SrcPort;

    private static unsafe UdpFlowKey? GetUdpFlowKey(WinDivertParseResult parsed)
    {
        if (parsed.UdpHeader == null) return null;
        if (parsed.IPV4Header != null)
            return new UdpFlowKey(parsed.IPV4Header->SrcAddr, parsed.UdpHeader->SrcPort, parsed.IPV4Header->DstAddr, parsed.UdpHeader->DstPort);
        if (parsed.IPV6Header != null)
            return new UdpFlowKey(parsed.IPV6Header->SrcAddr, parsed.UdpHeader->SrcPort, parsed.IPV6Header->DstAddr, parsed.UdpHeader->DstPort);
        return null;
    }

    private static unsafe AddressFamily FamilyOf(WinDivertParseResult parsed) =>
        parsed.IPV6Header == null ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;

    private static string? TryGetProcessName(int? pid)
    {
        if (pid is null) return null;
        try
        {
            using var proc = Process.GetProcessById(pid.Value);
            return proc.ProcessName + ".exe";
        }
        catch
        {
            return null;
        }
    }
}
