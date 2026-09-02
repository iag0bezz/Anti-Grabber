using AntiGrabber.Service;
using AntiGrabber.Service.FileWatch;
using AntiGrabber.Service.Ipc;
using AntiGrabber.Service.Network;
using AntiGrabber.Service.Rules;
using AntiGrabber.Shared;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntiGrabber", "logs");
builder.Services.AddSerilog(config => config
    .MinimumLevel.Information()
    .WriteTo.File(
        Path.Combine(logDir, "service-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        fileSizeLimitBytes: 10 * 1024 * 1024,
        rollOnFileSizeLimit: true));

builder.Services.AddWindowsService(o => o.ServiceName = "AntiGrabberService");

var whitelistPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "AntiGrabber", "rules.json");

builder.Services.AddSingleton(new DomainWhitelistStore(whitelistPath));
builder.Services.AddSingleton<CorrelationTracker>();
builder.Services.AddSingleton<MonitoredAppsState>();
builder.Services.AddSingleton<BlockStatsTracker>();
builder.Services.AddSingleton<IpcServer>();
builder.Services.Configure<RuleUpdateOptions>(builder.Configuration.GetSection("RuleUpdate"));

builder.Services.AddHostedService<StartupChecks>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<IpcServer>());
builder.Services.AddHostedService<NetworkFilterWorker>();
builder.Services.AddHostedService<TokenFileWatcher>();
builder.Services.AddHostedService<RuleUpdateService>();

var host = builder.Build();
host.Run();
