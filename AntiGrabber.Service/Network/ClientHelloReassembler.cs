using System.Net.Sockets;
using WindivertDotnet;

namespace AntiGrabber.Service.Network;

public enum ReassemblyStatus
{
    /// Ainda faltam bytes — pacote foi retido internamente, chamador não faz nada agora.
    Buffering,

    /// ClientHello completo, decisão de bloqueio pode ser tomada com Sni/LocalPort/Family.
    Ready,

    /// Cap de tamanho/timeout/limite de fluxos estourou — desiste, chamador deve
    /// encaminhar tudo que foi retido (fail-open, mesma filosofia do resto do sistema:
    /// sem certeza do domínio, não bloqueia).
    GiveUp,
}

public sealed class PendingFragment
{
    public required WinDivertPacket Packet { get; init; }
    public required WinDivertAddress Address { get; init; }
}

public readonly struct ReassemblyResult
{
    public required ReassemblyStatus Status { get; init; }
    public string? Sni { get; init; }
    public ushort LocalPort { get; init; }
    public AddressFamily Family { get; init; }
    public List<PendingFragment>? Flush { get; init; }

    /// Fluxos diferentes do que está sendo alimentado agora, varridos por inatividade
    /// nesta mesma chamada — também precisam ser encaminhados (fail-open) e descartados.
    public List<List<PendingFragment>>? ExpiredFlows { get; init; }
}

/// Reconstrói um ClientHello TLS espalhado por vários segmentos TCP. Sem isso, um
/// ClientHello fragmentado (comum com ECH/GREASE/muitas extensions) nunca é visto
/// inteiro por TlsSniParser e a conexão passa sem inspeção — ver TlsSniParser.
///
/// ponytail: limites fixos (não configuráveis), sweep de inatividade só roda quando
/// algum pacote chega (sem timer de fundo) — se o tráfego parar completamente com um
/// fluxo pendurado, ele só é liberado/descartado no próximo Feed() de qualquer fluxo,
/// não instantaneamente no timeout. Trocar por timer dedicado se isso virar problema
/// real (hoje não é: outro tráfego na mesma máquina aciona sweep dentro de segundos).
public sealed class ClientHelloReassembler : IDisposable
{
    private const int MaxBufferedBytesPerFlow = 32 * 1024;
    private const int MaxTrackedFlows = 512;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMilliseconds(750);

    private readonly Dictionary<TcpFlowKey, PendingFlow> _flows = new();

    public bool IsTracking(TcpFlowKey key) => _flows.ContainsKey(key);

    public ReassemblyResult Feed(
        TcpFlowKey key, uint seq, ReadOnlySpan<byte> payload,
        ushort localPort, AddressFamily family,
        WinDivertPacket packet, WinDivertAddress address)
    {
        var expired = SweepExpired(except: key);

        if (!_flows.TryGetValue(key, out var flow))
        {
            if (_flows.Count >= MaxTrackedFlows)
            {
                // Sem espaço pra rastrear mais um fluxo — decide com o que já veio agora,
                // sem esperar mais fragmentos (limite de memória, não limite de segurança).
                var single = new PendingFlow(localPort, family);
                single.Fragments.Add(new Fragment(seq, payload.ToArray(), packet.Clone(), address.Clone()));
                return GiveUp(single, expired);
            }

            flow = new PendingFlow(localPort, family);
            _flows[key] = flow;
        }

        if (flow.Fragments.Any(f => f.Seq == seq))
        {
            // Retransmissão exata de um fragmento já recebido — ignora, já temos esses bytes.
            return new ReassemblyResult { Status = ReassemblyStatus.Buffering, ExpiredFlows = expired };
        }

        flow.LastActivityUtc = DateTime.UtcNow;
        flow.TotalBytes += payload.Length;
        flow.Fragments.Add(new Fragment(seq, payload.ToArray(), packet.Clone(), address.Clone()));

        if (flow.TotalBytes > MaxBufferedBytesPerFlow)
        {
            _flows.Remove(key);
            return GiveUp(flow, expired);
        }

        flow.Fragments.Sort((a, b) => a.Seq.CompareTo(b.Seq));
        var combined = CombineContiguous(flow.Fragments);
        if (combined is null)
        {
            // Gap entre fragmentos (fragmento do meio ainda não chegou) — espera mais.
            return new ReassemblyResult { Status = ReassemblyStatus.Buffering, ExpiredFlows = expired };
        }

        var status = TlsSniParser.TryExtractSni(combined, out var sni);
        if (status == ClientHelloParseStatus.Incomplete)
            return new ReassemblyResult { Status = ReassemblyStatus.Buffering, ExpiredFlows = expired };

        _flows.Remove(key);
        if (status == ClientHelloParseStatus.Invalid)
            return GiveUp(flow, expired); // malformado mesmo com bytes completos — desiste

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

    private List<List<PendingFragment>>? SweepExpired(TcpFlowKey except)
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
        flow.Fragments
            .OrderBy(f => f.Seq)
            .Select(f => new PendingFragment { Packet = f.Packet, Address = f.Address })
            .ToList();

    /// Concatena só o prefixo contíguo (sem buracos) começando no primeiro fragmento —
    /// que é sempre o início do record TLS, é o que fez o fluxo começar a ser rastreado.
    private static byte[]? CombineContiguous(List<Fragment> sortedFragments)
    {
        var buffer = new List<byte>();
        uint? expectedSeq = null;

        foreach (var f in sortedFragments)
        {
            if (expectedSeq is null) expectedSeq = f.Seq;
            else if (f.Seq != expectedSeq.Value) break;

            buffer.AddRange(f.Payload);
            expectedSeq = unchecked(f.Seq + (uint)f.Payload.Length);
        }

        return buffer.Count == 0 ? null : buffer.ToArray();
    }

    private sealed class PendingFlow(ushort localPort, AddressFamily family)
    {
        public readonly List<Fragment> Fragments = new();
        public DateTime LastActivityUtc = DateTime.UtcNow;
        public int TotalBytes;
        public readonly ushort LocalPort = localPort;
        public readonly AddressFamily Family = family;
    }

    private readonly record struct Fragment(uint Seq, byte[] Payload, WinDivertPacket Packet, WinDivertAddress Address);
}
