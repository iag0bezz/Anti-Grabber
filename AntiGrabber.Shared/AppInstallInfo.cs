namespace AntiGrabber.Shared;

public enum DetectionMethod
{
    RunningProcess,
    Registry,
    Shortcut,
    AppDataDefaultPath,
    DiskScan,
}

public sealed record AppInstallInfo(
    string AppId,
    string DisplayName,
    string InstallPath,
    DetectionMethod DetectedBy,
    IReadOnlyList<string> SensitiveDirectories,
    IReadOnlyList<string> ProcessNames,
    IReadOnlyList<string> AllowedDomains);
