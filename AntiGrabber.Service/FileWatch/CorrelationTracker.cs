using System.Collections.Concurrent;

namespace AntiGrabber.Service.FileWatch;

public sealed class CorrelationTracker
{
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(10);
    private readonly ConcurrentDictionary<int, (DateTime When, string Path)> _lastSensitiveFileAccess = new();

    public void RecordFileAccess(int pid, string path) => _lastSensitiveFileAccess[pid] = (DateTime.UtcNow, path);

    public bool HasRecentFileAccess(int pid)
        => _lastSensitiveFileAccess.TryGetValue(pid, out var last)
           && DateTime.UtcNow - last.When <= CorrelationWindow;

    public string? TryGetRecentFilePath(int pid)
        => _lastSensitiveFileAccess.TryGetValue(pid, out var last) && DateTime.UtcNow - last.When <= CorrelationWindow
            ? last.Path
            : null;
}
