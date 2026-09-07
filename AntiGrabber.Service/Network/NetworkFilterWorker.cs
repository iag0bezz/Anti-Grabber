using System.Diagnostics;
using System.Net.Sockets;
using AntiGrabber.Service.FileWatch;
using AntiGrabber.Service.Ipc;
using AntiGrabber.Shared;
using WindivertDotnet;

namespace AntiGrabber.Service.Network;

public sealed class NetworkFilterWorker : BackgroundService
{
    private readonly ILogger<NetworkFilterWorker> _logger;
    private readonly DomainWhitelistStore _whitelist;
    private readonly CorrelationTracker _correlationTracker;
    private readonly IpcServer _ipcServer;
    private readonly BlockStatsTracker _blockStats;

    public NetworkFilterWorker(
        ILogger<NetworkFilterWorker> logger,
        DomainWhitelistStore whitelist,
        CorrelationTracker correlationTracker,
        IpcServer ipcServer,
        BlockStatsTracker blockStats)
    {
        _logger = logger;
        _whitelist = whitelist;
        _correlationTracker = correlationTracker;
        _ipcServer = ipcServer;
        _blockStats = blockStats;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        WinDivert divert;
        try
        {
            const string filter = "outbound and tcp.DstPort == 443";
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

                var shouldForward = await ProcessPacketAsync(packet, stoppingToken);
                if (shouldForward)
                {
                    try { await divert.SendAsync(packet, address, stoppingToken); }
                    catch (Exception ex) { _logger.LogWarning(ex, "Erro reenviando pacote."); }
                }
            }
        }
    }

    private async Task<bool> ProcessPacketAsync(WinDivertPacket packet, CancellationToken ct)
    {
        if (!TryParseClientHello(packet, out var sni, out var localPort, out var family))
            return true;

        if (!_whitelist.IsSensitiveDomain(sni)) return true;

        var pid = TcpProcessResolver.ResolvePidByLocalPort(localPort, family);

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

    private static unsafe bool TryParseClientHello(WinDivertPacket packet, out string sni, out ushort localPort, out AddressFamily family)
    {
        sni = "";
        localPort = 0;
        family = AddressFamily.InterNetwork;

        WinDivertParseResult parsed;
        try { parsed = packet.GetParseResult(); }
        catch { return false; }

        if (parsed.Protocol != ProtocolType.Tcp || parsed.TcpHeader == null || parsed.DataLength == 0)
            return false;

        // TODO(reassembly): status Incomplete hoje é tratado igual Invalid (forward sem
        // decisão) — ClientHello fragmentado em vários segmentos TCP ainda escapa da
        // inspeção. Reassembly por fluxo entra em etapa separada.
        var status = TlsSniParser.TryExtractSni(parsed.DataSpan, out var extracted);
        if (status != ClientHelloParseStatus.Complete || extracted is null) return false;

        sni = extracted;
        localPort = parsed.TcpHeader->SrcPort;
        family = parsed.IPV6Header == null ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        return true;
    }

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
