using System.Text.Json.Serialization;

namespace AntiGrabber.Shared;

public enum IpcMessageType
{
    Ping,
    Pong,
    Status,
    BlockEvent,
    AllowAlwaysCommand,
    AllowAlwaysAck,
    RulesSnapshot,
    RemoveRuleCommand,
    SetRuleEnabledCommand,
}

public sealed class IpcEnvelope
{
    [JsonPropertyName("type")]
    public IpcMessageType Type { get; set; }

    [JsonPropertyName("status")]
    public ServiceStatusPayload? Status { get; set; }

    [JsonPropertyName("blockEvent")]
    public BlockEventPayload? BlockEvent { get; set; }

    [JsonPropertyName("allowAlways")]
    public AllowAlwaysPayload? AllowAlways { get; set; }

    [JsonPropertyName("rulesSnapshot")]
    public RulesSnapshotPayload? RulesSnapshot { get; set; }

    [JsonPropertyName("removeRule")]
    public AllowAlwaysPayload? RemoveRule { get; set; }

    [JsonPropertyName("setRuleEnabled")]
    public SetRuleEnabledPayload? SetRuleEnabled { get; set; }
}

public sealed class ServiceStatusPayload
{
    [JsonPropertyName("state")] public string State { get; set; } = "idle";
    [JsonPropertyName("monitoredApps")] public string[] MonitoredApps { get; set; } = Array.Empty<string>();
    [JsonPropertyName("blocksLast24h")] public int BlocksLast24h { get; set; }
}

public sealed class BlockEventPayload
{
    [JsonPropertyName("timestamp")] public DateTimeOffset Timestamp { get; set; }
    [JsonPropertyName("processName")] public string ProcessName { get; set; } = "";
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("plainLanguageMessage")] public string PlainLanguageMessage { get; set; } = "";
    [JsonPropertyName("correlatedFileAccess")] public bool CorrelatedFileAccess { get; set; }
    [JsonPropertyName("pid")] public int? Pid { get; set; }
    [JsonPropertyName("localPort")] public int LocalPort { get; set; }
    [JsonPropertyName("correlatedFilePath")] public string? CorrelatedFilePath { get; set; }
}

public sealed class AllowAlwaysPayload
{
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("processName")] public string ProcessName { get; set; } = "";
}

public sealed class RuleEntryPayload
{
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("processName")] public string ProcessName { get; set; } = "";
    [JsonPropertyName("enabled")] public bool Enabled { get; set; }
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; set; }
}

public sealed class RulesSnapshotPayload
{
    [JsonPropertyName("rules")] public RuleEntryPayload[] Rules { get; set; } = Array.Empty<RuleEntryPayload>();
}

public sealed class SetRuleEnabledPayload
{
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("processName")] public string ProcessName { get; set; } = "";
    [JsonPropertyName("enabled")] public bool Enabled { get; set; }
}
