using AntiGrabber.Service.FileWatch;
using AntiGrabber.Shared;

namespace AntiGrabber.Service.FileWatch;

public sealed class TokenFileWatcher : BackgroundService
{
    private readonly ILogger<TokenFileWatcher> _logger;
    private readonly CorrelationTracker _correlationTracker;
    private readonly List<FileSystemWatcher> _watchers = new();

    public TokenFileWatcher(ILogger<TokenFileWatcher> logger, CorrelationTracker correlationTracker)
    {
        _logger = logger;
        _correlationTracker = correlationTracker;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var locator = new UnifiedAppLocator();
        var installs = locator.DetectAll();

        foreach (var app in installs)
        {
            foreach (var dir in app.SensitiveDirectories)
            {
                TryWatchDirectory(dir, app.DisplayName);
            }
        }

        _logger.LogInformation("TokenFileWatcher observando {Count} diretórios sensíveis.", _watchers.Count);

        stoppingToken.Register(() =>
        {
            foreach (var w in _watchers) w.Dispose();
        });

        return Task.Delay(Timeout.Infinite, stoppingToken).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    private void TryWatchDirectory(string dir, string appName)
    {
        try
        {
            var existingDir = Directory.Exists(dir) ? dir : Path.GetDirectoryName(dir);
            if (existingDir is null || !Directory.Exists(existingDir)) return;

            var watcher = new FileSystemWatcher(existingDir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite | NotifyFilters.FileName,
                EnableRaisingEvents = true,
            };

            watcher.Changed += (_, e) => OnSensitiveAccess(appName, e.FullPath);
            watcher.Created += (_, e) => OnSensitiveAccess(appName, e.FullPath);

            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Não foi possível observar {Dir} de {App}.", dir, appName);
        }
    }

    private void OnSensitiveAccess(string appName, string path)
    {
        var pid = FileAccessProcessResolver.TryResolveAccessingPid(path);
        if (pid is not null)
        {
            _correlationTracker.RecordFileAccess(pid.Value, path);
        }

        _logger.LogInformation(
            "Acesso a diretório sensível de {App}: {FileName} (pid={Pid})",
            appName, Path.GetFileName(path), pid?.ToString() ?? "desconhecido");
    }
}
