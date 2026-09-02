using System.Collections.Concurrent;

namespace AntiGrabber.Service.FileWatch;

public sealed class CorrelationTracker
{
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(10);
    private readonly ConcurrentDictionary<int, DateTime> _lastSensitiveFileAccess = new();

    public void RecordFileAccess(int pid) => _lastSensitiveFileAccess[pid] = DateTime.UtcNow;

    public bool HasRecentFileAccess(int pid)
        => _lastSensitiveFileAccess.TryGetValue(pid, out var last)
           && DateTime.UtcNow - last <= CorrelationWindow;
}
