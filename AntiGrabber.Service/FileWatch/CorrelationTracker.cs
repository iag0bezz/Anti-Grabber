using System.Collections.Concurrent;

namespace AntiGrabber.Service.FileWatch;

public sealed class CorrelationTracker
{
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(10);
    // Arquivo de conta lido por processo de fora: janela maior — stealer costuma juntar
    // vários alvos (navegador, Discord, launchers) antes de mandar tudo de uma vez.
    public static readonly TimeSpan AccountReadWindow = TimeSpan.FromSeconds(60);

    private readonly ConcurrentDictionary<int, (DateTime When, string Path)> _lastSensitiveFileAccess = new();
    private readonly ConcurrentDictionary<int, (DateTime When, string Path, string App)> _lastAccountRead = new();
    private readonly Func<DateTime> _now;
    private DateTime _lastAnyAccountRead = DateTime.MinValue;

    public CorrelationTracker(Func<DateTime>? clock = null) => _now = clock ?? (() => DateTime.UtcNow);

    public void RecordFileAccess(int pid, string path) => _lastSensitiveFileAccess[pid] = (_now(), path);

    public void RecordAccountRead(int pid, string path, string appName)
    {
        var now = _now();
        _lastAccountRead[pid] = (now, path, appName);
        _lastSensitiveFileAccess[pid] = (now, path);
        _lastAnyAccountRead = now;
    }

    public bool HasRecentFileAccess(int pid)
        => _lastSensitiveFileAccess.TryGetValue(pid, out var last)
           && _now() - last.When <= CorrelationWindow;

    public string? TryGetRecentFilePath(int pid)
        => _lastSensitiveFileAccess.TryGetValue(pid, out var last) && _now() - last.When <= CorrelationWindow
            ? last.Path
            : null;

    /// Atalho do caminho do pacote: sem leitura de conta recente em lugar nenhum, domínio
    /// não sensível passa direto sem resolver PID.
    public bool AnyRecentAccountRead => _now() - _lastAnyAccountRead <= AccountReadWindow;

    public (string Path, string App)? TryGetRecentAccountRead(int pid)
        => _lastAccountRead.TryGetValue(pid, out var last) && _now() - last.When <= AccountReadWindow
            ? (last.Path, last.App)
            : null;
}
