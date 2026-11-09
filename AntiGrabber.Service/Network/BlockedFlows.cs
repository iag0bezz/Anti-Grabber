namespace AntiGrabber.Service.Network;

/// Fluxos (5-tuple) cujo ClientHello já foi bloqueado. Todo pacote seguinte do mesmo
/// fluxo — retransmissão do ClientHello, segmento de continuação, FIN — é descartado
/// ANTES de qualquer caminho fail-open do parser/reassembler. Sem isso, a retransmissão
/// do 1º segmento de um ClientHello fragmentado (ML-KEM deixa ele com ~1,8KB) ficava
/// bufferizada, expirava, era liberada, e o 2º segmento passava como Invalid: conexão
/// completa com um único "Bloqueado" no log.
///
/// Sem lock: só é usado pelo laço único de recepção do NetworkFilterWorker.
public sealed class BlockedFlows<TKey> where TKey : notnull
{
    private readonly Dictionary<TKey, DateTime> _until = new();
    private readonly TimeSpan _ttl;
    private DateTime _nextSweepUtc;

    public BlockedFlows(TimeSpan ttl) => _ttl = ttl;

    public int Count => _until.Count;

    public void Add(TKey key, DateTime nowUtc) => _until[key] = nowUtc + _ttl;

    public bool IsBlocked(TKey key, DateTime nowUtc)
    {
        Sweep(nowUtc);
        return _until.TryGetValue(key, out var until) && until > nowUtc;
    }

    private void Sweep(DateTime nowUtc)
    {
        if (nowUtc < _nextSweepUtc) return;
        _nextSweepUtc = nowUtc + _ttl;
        foreach (var key in _until.Where(p => p.Value <= nowUtc).Select(p => p.Key).ToList())
            _until.Remove(key);
    }
}
