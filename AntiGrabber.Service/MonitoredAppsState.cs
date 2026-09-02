namespace AntiGrabber.Service;

public sealed class MonitoredAppsState
{
    public IReadOnlyList<string> AppNames { get; private set; } = Array.Empty<string>();

    public void Set(IEnumerable<string> names) => AppNames = names.ToList();
}
