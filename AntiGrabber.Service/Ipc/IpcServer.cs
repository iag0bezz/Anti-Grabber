using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Channels;
using AntiGrabber.Service.Rules;
using AntiGrabber.Shared;

namespace AntiGrabber.Service.Ipc;

public sealed class IpcServer : BackgroundService
{
    private readonly ILogger<IpcServer> _logger;
    private readonly DomainWhitelistStore _whitelist;
    private readonly MonitoredAppsState _monitoredApps;
    private readonly BlockStatsTracker _blockStats;
    private readonly RuleRevalidationSignal _revalidationSignal;
    private volatile ChannelWriter<IpcEnvelope>? _outbound;
    private string _currentState = "idle";
    private RulesStatusPayload _lastRulesStatus = new() { LastCheckedUtc = null, LastCheckOk = false };

    public IpcServer(
        ILogger<IpcServer> logger,
        DomainWhitelistStore whitelist,
        MonitoredAppsState monitoredApps,
        BlockStatsTracker blockStats,
        RuleRevalidationSignal revalidationSignal)
    {
        _logger = logger;
        _whitelist = whitelist;
        _monitoredApps = monitoredApps;
        _blockStats = blockStats;
        _revalidationSignal = revalidationSignal;
    }

    public async Task PublishAsync(IpcEnvelope envelope)
    {
        var outbound = _outbound;
        if (outbound is null) return;
        await outbound.WriteAsync(envelope);
    }

    public Task PublishRulesStatusAsync(DateTimeOffset? lastCheckedUtc, bool ok)
    {
        _lastRulesStatus = new RulesStatusPayload { LastCheckedUtc = lastCheckedUtc, LastCheckOk = ok };
        return PublishAsync(new IpcEnvelope { Type = IpcMessageType.RulesStatus, RulesStatus = _lastRulesStatus });
    }

    public Task PublishStatusAsync(string state)
    {
        _currentState = state;
        return PublishAsync(new IpcEnvelope
        {
            Type = IpcMessageType.Status,
            Status = new ServiceStatusPayload
            {
                State = state,
                MonitoredApps = _monitoredApps.AppNames.ToArray(),
                BlocksLast24h = _blockStats.CountLast24h(),
            },
        });
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var pipe = CreatePipeServer();
                await pipe.WaitForConnectionAsync(stoppingToken);
                await HandleClientAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Erro no pipe IPC, reabrindo.");
                await Task.Delay(1000, stoppingToken);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        var channel = Channel.CreateUnbounded<IpcEnvelope>();
        _outbound = channel.Writer;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);

        var writerTask = Task.Run(async () =>
        {
            try
            {
                await foreach (var envelope in channel.Reader.ReadAllAsync(cts.Token))
                {
                    await PipeMessageFramer.WriteAsync(pipe, envelope, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
        }, cts.Token);

        await PublishStatusAsync(_currentState);
        await PublishRulesSnapshotAsync();
        await PublishAsync(new IpcEnvelope { Type = IpcMessageType.RulesStatus, RulesStatus = _lastRulesStatus });

        try
        {
            while (pipe.IsConnected && !cts.IsCancellationRequested)
            {
                var envelope = await PipeMessageFramer.ReadAsync(pipe, cts.Token);
                if (envelope is null) break;
                await HandleInboundAsync(envelope);
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        finally
        {
            cts.Cancel();
            channel.Writer.TryComplete();
            _outbound = null;
            await writerTask.ConfigureAwait(false);
        }
    }

    private async Task HandleInboundAsync(IpcEnvelope envelope)
    {
        switch (envelope.Type)
        {
            case IpcMessageType.Ping:
                await PublishAsync(new IpcEnvelope { Type = IpcMessageType.Pong });
                break;

            case IpcMessageType.AllowAlwaysCommand when envelope.AllowAlways is not null:
                _whitelist.AllowAlways(envelope.AllowAlways.Domain, envelope.AllowAlways.ProcessName);
                _logger.LogInformation(
                    "Allowlist manual: {Process} liberado para {Domain}.",
                    envelope.AllowAlways.ProcessName, envelope.AllowAlways.Domain);
                await PublishAsync(new IpcEnvelope { Type = IpcMessageType.AllowAlwaysAck });
                await PublishRulesSnapshotAsync();
                break;

            case IpcMessageType.RemoveRuleCommand when envelope.RemoveRule is not null:
                _whitelist.RemoveRule(envelope.RemoveRule.Domain, envelope.RemoveRule.ProcessName);
                _logger.LogInformation(
                    "Allowlist manual: exceção revogada {Process}/{Domain}.",
                    envelope.RemoveRule.ProcessName, envelope.RemoveRule.Domain);
                await PublishRulesSnapshotAsync();
                break;

            case IpcMessageType.SetRuleEnabledCommand when envelope.SetRuleEnabled is not null:
                _whitelist.SetRuleEnabled(
                    envelope.SetRuleEnabled.Domain, envelope.SetRuleEnabled.ProcessName, envelope.SetRuleEnabled.Enabled);
                _logger.LogInformation(
                    "Allowlist manual: exceção {Process}/{Domain} {State}.",
                    envelope.SetRuleEnabled.ProcessName, envelope.SetRuleEnabled.Domain,
                    envelope.SetRuleEnabled.Enabled ? "reativada" : "desativada");
                await PublishRulesSnapshotAsync();
                break;

            case IpcMessageType.RevalidateRulesCommand:
                _revalidationSignal.Request();
                break;
        }
    }

    private Task PublishRulesSnapshotAsync()
    {
        var rules = _whitelist.GetUserRules()
            .Select(r => new RuleEntryPayload
            {
                Domain = r.Domain,
                ProcessName = r.ProcessName,
                Enabled = r.Enabled,
                CreatedAt = r.CreatedAt,
            })
            .ToArray();

        return PublishAsync(new IpcEnvelope
        {
            Type = IpcMessageType.RulesSnapshot,
            RulesSnapshot = new RulesSnapshotPayload { Rules = rules },
        });
    }

    private static NamedPipeServerStream CreatePipeServer()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AnonymousSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));

        return NamedPipeServerStreamAcl.Create(
            PipeMessageFramer.PipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            pipeSecurity: security);
    }
}
