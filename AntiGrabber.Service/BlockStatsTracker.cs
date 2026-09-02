using System.Collections.Concurrent;

namespace AntiGrabber.Service;

public sealed class BlockStatsTracker
{
    private readonly ConcurrentQueue<DateTimeOffset> _blocks = new();

    public void RecordBlock()
    {
        _blocks.Enqueue(DateTimeOffset.UtcNow);
        Trim();
    }

    public int CountLast24h()
    {
        Trim();
        return _blocks.Count;
    }

    private void Trim()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-24);
        while (_blocks.TryPeek(out var oldest) && oldest < cutoff)
            _blocks.TryDequeue(out _);
    }
}
