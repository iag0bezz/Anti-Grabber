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
    private readonly NetworkFilterOptions _options;
    private readonly ClientHelloReassembler _reassembler = new();
    private readonly QuicClientHelloReassembler _quicReassembler = new();

    public NetworkFilterWorker(
        ILogger<NetworkFilterWorker> logger,
        DomainWhitelistStore whitelist,
        CorrelationTracker correlationTracker,
        IpcServer ipcServer,
        BlockStatsTracker blockStats,
        IOptions<NetworkFilterOptions> options)
    {
        _logger = logger;
        _whitelist = whitelist;
        _correlationTracker = correlationTracker;
        _ipcServer = ipcServer;
        _blockStats = blockStats;
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

        // Fragmento de continuação de um ClientHello já em reassembly (não começa com
        // 0x16 — é só o meio de um record TLS partido em vários segmentos TCP).
        if (flowKey is { } trackedKey && parsed.DataLength > 0 && _reassembler.IsTracking(trackedKey))
        {
            var result = _reassembler.Feed(
                trackedKey, SeqOf(parsed), parsed.DataSpan,
                SrcPortOf(parsed), FamilyOf(parsed), packet, address);
            await HandleReassemblyResultAsync(divert, result, ct);
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
            await HandleReassemblyResultAsync(divert, result, ct);
            return;
        }

        // status == Complete — fast path, ClientHello vinha inteiro num pacote só.
        if (sni is null)
        {
            await ForwardAsync(divert, packet, address, ct);
            return;
        }

        var allow = await DecideAsync(sni, SrcPortOf(parsed), FamilyOf(parsed), isUdp: false, ct);
        if (allow) await ForwardAsync(divert, packet, address, ct);
    }

    /// Caminho QUIC/UDP 443 — só inspeciona o Initial packet do handshake (onde o
    /// ClientHello viaja em claro, ver QuicInitialCrypto). Pacotes de fases seguintes
    /// (Handshake/1-RTT) não dá pra decifrar sem os segredos negociados depois do
    /// Initial, e por isso passam liberados (fail-open) — decisão já foi tomada aqui.
    private async Task ProcessQuicPacketAsync(WinDivert divert, WinDivertPacket packet, WinDivertAddress address, WinDivertParseResult parsed, CancellationToken ct)
    {
        var flowKey = GetUdpFlowKey(parsed);
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
        await HandleQuicReassemblyResultAsync(divert, result, ct);
    }

    private async Task HandleReassemblyResultAsync(WinDivert divert, ReassemblyResult result, CancellationToken ct)
    {
        switch (result.Status)
        {
            case ReassemblyStatus.Buffering:
                break; // aguardando mais fragmentos — pacote atual já foi clonado e retido

            case ReassemblyStatus.GiveUp:
                await FlushAsync(divert, result.Flush!, forward: true, ct);
                break;

            case ReassemblyStatus.Ready:
                var allow = await DecideAsync(result.Sni!, result.LocalPort, result.Family, isUdp: false, ct);
                await FlushAsync(divert, result.Flush!, forward: allow, ct);
                break;
        }

        if (result.ExpiredFlows is { Count: > 0 } expired)
            foreach (var flow in expired)
                await FlushAsync(divert, flow, forward: true, ct);
    }

    private async Task HandleQuicReassemblyResultAsync(WinDivert divert, ReassemblyResult result, CancellationToken ct)
    {
        switch (result.Status)
        {
            case ReassemblyStatus.Buffering:
                break;

            case ReassemblyStatus.GiveUp:
                await FlushAsync(divert, result.Flush!, forward: true, ct);
                break;

            case ReassemblyStatus.Ready:
                var allow = await DecideAsync(result.Sni!, result.LocalPort, result.Family, isUdp: true, ct);
                await FlushAsync(divert, result.Flush!, forward: allow, ct);
                break;
        }

        if (result.ExpiredFlows is { Count: > 0 } expired)
            foreach (var flow in expired)
                await FlushAsync(divert, flow, forward: true, ct);
    }

    private async Task<bool> DecideAsync(string sni, ushort localPort, AddressFamily family, bool isUdp, CancellationToken ct)
    {
        if (!_whitelist.IsSensitiveDomain(sni)) return true;

        var pid = isUdp
            ? UdpProcessResolver.ResolvePidByLocalPort(localPort, family)
            : TcpProcessResolver.ResolvePidByLocalPort(localPort, family);

        var processName = TryGetProcessName(pid);
        if (processName is not null && _whitelist.IsAllowed(sni, processName))
            return true;

        var correlatedFileAccess = pid is not null && _correlationTracker.HasRecentFileAccess(pid.Value);
        var correlatedFilePath = pid is not null ? _correlationTracker.TryGetRecentFilePath(pid.Value) : null;
        _blockStats.RecordBlock();

        _logger.LogWarning(
            "Bloqueado: {Process} (pid={Pid}) tentou conectar em {Domain}. Acesso a arquivo sensível recente: {Correlated}",
            processName ?? "desconhecido", pid?.ToString() ?? "?", sni, correlatedFileAccess);

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
                PlainLanguageMessage = correlatedFileAccess
                    ? $"Bloqueamos uma tentativa de roubo: {processName ?? "um programa"} tentou enviar dados para {sni} logo após acessar seus arquivos."
                    : $"Bloqueamos uma conexão suspeita: {processName ?? "um programa"} tentou falar com {sni} sem autorização.",
            },
        });
        await _ipcServer.PublishStatusAsync("recentBlock");

        return false;
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
