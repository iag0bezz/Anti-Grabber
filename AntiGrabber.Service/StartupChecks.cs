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

        // Liberações dos apps (Discord→discord.com etc.) precisam estar semeadas antes do
        // filtro de rede subir — esta fase é rápida. A varredura de disco (launcher em pasta
        // fora do padrão) vem depois em segundo plano e só soma; antes ela travava o host
        // por ~80s, e nesse tempo o filtro de rede nem estava rodando.
        var locator = new UnifiedAppLocator();
        Seed(locator.DetectAll(deepScan: false));
        await _ipcServer.PublishStatusAsync("active");

        _ = Task.Run(() =>
        {
            try { Seed(locator.DetectAll()); }
            catch (Exception ex) { _logger.LogWarning(ex, "Detecção completa de apps falhou — seguindo com a detecção rápida."); }
        }, stoppingToken);
    }

    private void Seed(IReadOnlyList<AppInstallInfo> installs)
    {
        _whitelist.SeedFromCatalog(installs);
        _monitoredApps.Set(installs.Select(a => a.DisplayName));
        _logger.LogInformation(
            "Apps monitorados detectados: {Apps}",
            string.Join(", ", installs.Select(a => $"{a.DisplayName} ({a.DetectedBy})")));
    }
}
