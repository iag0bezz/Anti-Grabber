using AntiGrabber.Service.Ipc;
using AntiGrabber.Shared;

namespace AntiGrabber.Service;

public sealed class StartupChecks : BackgroundService
{
    private readonly ILogger<StartupChecks> _logger;
    private readonly DomainWhitelistStore _whitelist;
    private readonly MonitoredAppsState _monitoredApps;
    private readonly IpcServer _ipcServer;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly IConfiguration _config;

    public StartupChecks(
        ILogger<StartupChecks> logger,
        DomainWhitelistStore whitelist,
        MonitoredAppsState monitoredApps,
        IpcServer ipcServer,
        IHostApplicationLifetime lifetime,
        IConfiguration config)
    {
        _logger = logger;
        _whitelist = whitelist;
        _monitoredApps = monitoredApps;
        _ipcServer = ipcServer;
        _lifetime = lifetime;
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var enforceIntegrity = _config.GetValue("Integrity:Enforce", false);
        var signed = BinaryIntegrityChecker.VerifyCurrentExecutable();

        if (!signed)
        {
            _logger.LogWarning("Assinatura digital do executável não pôde ser verificada.");
            if (enforceIntegrity)
            {
                _logger.LogCritical("Integrity:Enforce=true — recusando iniciar com binário não assinado.");
                _lifetime.StopApplication();
                return;
            }
        }
        else
        {
            _logger.LogInformation("Assinatura digital do executável verificada com sucesso.");
        }

        var locator = new UnifiedAppLocator();
        var installs = locator.DetectAll();
        _whitelist.SeedFromCatalog(installs);
        _monitoredApps.Set(installs.Select(a => a.DisplayName));

        _logger.LogInformation(
            "Apps monitorados detectados: {Apps}",
            string.Join(", ", installs.Select(a => $"{a.DisplayName} ({a.DetectedBy})")));

        await _ipcServer.PublishStatusAsync("active");
    }
}
