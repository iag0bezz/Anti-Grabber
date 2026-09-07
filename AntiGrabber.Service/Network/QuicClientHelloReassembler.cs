using System.Net.Sockets;
using WindivertDotnet;

namespace AntiGrabber.Service.Network;

/// Reconstrói a mensagem de handshake ClientHello a partir de frames CRYPTO
/// espalhados por vários pacotes QUIC Initial (RFC 9000 §19.6) — equivalente ao
/// ClientHelloReassembler do caminho TCP, mas mais simples: o offset de cada
/// CRYPTO frame já é absoluto dentro do stream de handshake (não precisa lidar
/// com sequence number de TCP), então "contíguo" é sempre "a partir do offset 0".
///
/// ponytail: mesmos limites fixos do reassembler TCP (32KB/fluxo, 512 fluxos,
/// sweep de inatividade só roda quando algum pacote chega). Ver ClientHelloReassembler
/// pra justificativa completa — a mesma se aplica aqui.
public sealed class QuicClientHelloReassembler : IDisposable
{
    private const int MaxBufferedBytesPerFlow = 32 * 1024;
    private const int MaxTrackedFlows = 512;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMilliseconds(750);

    private readonly Dictionary<UdpFlowKey, PendingFlow> _flows = new();

    public ReassemblyResult Feed(
        UdpFlowKey key, List<QuicCryptoFrameExtractor.CryptoChunk> chunks,
        ushort localPort, AddressFamily family,
        WinDivertPacket packet, WinDivertAddress address)
    {
        var expired = SweepExpired(except: key);

        if (!_flows.TryGetValue(key, out var flow))
        {
            if (_flows.Count >= MaxTrackedFlows)
            {
                var single = new PendingFlow(localPort, family);
                single.Fragments.Add(new Fragment(packet.Clone(), address.Clone()));
                return GiveUp(single, expired);
            }

            flow = new PendingFlow(localPort, family);
            _flows[key] = flow;
        }

        flow.LastActivityUtc = DateTime.UtcNow;
        flow.Fragments.Add(new Fragment(packet.Clone(), address.Clone()));

        foreach (var chunk in chunks)
        {
            if (flow.ChunksByOffset.ContainsKey(chunk.Offset)) continue; // retransmissão exata
            flow.ChunksByOffset[chunk.Offset] = chunk.Data;
            flow.TotalBytes += chunk.Data.Length;
        }

        if (flow.TotalBytes > MaxBufferedBytesPerFlow)
        {
            _flows.Remove(key);
            return GiveUp(flow, expired);
        }

        var combined = CombineFromZero(flow.ChunksByOffset);
        if (combined is null || combined.Length < 4)
            return new ReassemblyResult { Status = ReassemblyStatus.Buffering, ExpiredFlows = expired };

        if (combined[0] != 0x01) // msg_type: client_hello
        {
            _flows.Remove(key);
            return GiveUp(flow, expired);
        }

        var bodyLen = (combined[1] << 16) | (combined[2] << 8) | combined[3];
        var totalLen = 4 + bodyLen;
        if (combined.Length < totalLen)
            return new ReassemblyResult { Status = ReassemblyStatus.Buffering, ExpiredFlows = expired };

        _flows.Remove(key);

        // TlsSniParser espera um record TLS completo — o CRYPTO frame do QUIC carrega
        // só a mensagem de handshake crua (sem o record layer, QUIC não usa). Envelope
        // fake de 5 bytes reaproveita o parser existente sem duplicar a lógica dele.
        var handshake = combined.AsSpan(0, totalLen);
        var withFakeRecordHeader = new byte[5 + handshake.Length];
        withFakeRecordHeader[0] = 0x16;
        withFakeRecordHeader[3] = (byte)(handshake.Length >> 8);
        withFakeRecordHeader[4] = (byte)handshake.Length;
        handshake.CopyTo(withFakeRecordHeader.AsSpan(5));

        var status = TlsSniParser.TryExtractSni(withFakeRecordHeader, out var sni);
        if (status != ClientHelloParseStatus.Complete)
            return GiveUp(flow, expired);

        return new ReassemblyResult
        {
            Status = ReassemblyStatus.Ready,
            Sni = sni,
            LocalPort = flow.LocalPort,
            Family = flow.Family,
            Flush = ToPendingFragments(flow),
            ExpiredFlows = expired,
        };
    }

    public void Dispose()
    {
        foreach (var flow in _flows.Values)
            foreach (var f in flow.Fragments) { f.Packet.Dispose(); f.Address.Dispose(); }
        _flows.Clear();
    }

    private List<List<PendingFragment>>? SweepExpired(UdpFlowKey except)
    {
        List<List<PendingFragment>>? result = null;
        var now = DateTime.UtcNow;

        foreach (var key in _flows.Keys.ToList())
        {
            if (key.Equals(except)) continue;

            var flow = _flows[key];
            if (now - flow.LastActivityUtc < IdleTimeout) continue;

            _flows.Remove(key);
            result ??= new List<List<PendingFragment>>();
            result.Add(ToPendingFragments(flow));
        }

        return result;
    }

    private static ReassemblyResult GiveUp(PendingFlow flow, List<List<PendingFragment>>? expired) => new()
    {
        Status = ReassemblyStatus.GiveUp,
        LocalPort = flow.LocalPort,
        Family = flow.Family,
        Flush = ToPendingFragments(flow),
        ExpiredFlows = expired,
    };

    private static List<PendingFragment> ToPendingFragments(PendingFlow flow) =>
        flow.Fragments.Select(f => new PendingFragment { Packet = f.Packet, Address = f.Address }).ToList();

    /// Concatena os chunks de CRYPTO a partir do offset 0, parando no primeiro buraco.
    private static byte[]? CombineFromZero(SortedDictionary<ulong, byte[]> chunksByOffset)
    {
        if (!chunksByOffset.ContainsKey(0)) return null;

        var buffer = new List<byte>();
        ulong expectedOffset = 0;

        foreach (var (offset, data) in chunksByOffset)
        {
            if (offset != expectedOffset) break;
            buffer.AddRange(data);
            expectedOffset += (ulong)data.Length;
        }

        return buffer.Count == 0 ? null : buffer.ToArray();
    }

    private sealed class PendingFlow(ushort localPort, AddressFamily family)
    {
        public readonly List<Fragment> Fragments = new();
        public readonly SortedDictionary<ulong, byte[]> ChunksByOffset = new();
        public DateTime LastActivityUtc = DateTime.UtcNow;
        public int TotalBytes;
        public readonly ushort LocalPort = localPort;
        public readonly AddressFamily Family = family;
    }

    private readonly record struct Fragment(WinDivertPacket Packet, WinDivertAddress Address);
}
