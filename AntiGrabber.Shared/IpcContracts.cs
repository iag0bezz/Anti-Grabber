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
    RevalidateRulesCommand,
    RulesStatus,
    InvestigationEvent,
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

    [JsonPropertyName("rulesStatus")]
    public RulesStatusPayload? RulesStatus { get; set; }

    [JsonPropertyName("investigation")]
    public InvestigationPayload? Investigation { get; set; }
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
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "TCP";
    // Preenchido quando o mesmo PID já foi investigado antes; senão chega depois via InvestigationEvent.
    [JsonPropertyName("investigation")] public InvestigationPayload? Investigation { get; set; }
}

/// Investigação feita em segundo plano depois de um bloqueio — nunca atrasa nem
/// muda a decisão, só documenta pra validação manual.
public sealed class InvestigationPayload
{
    [JsonPropertyName("timestamp")] public DateTimeOffset Timestamp { get; set; }
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("processName")] public string ProcessName { get; set; } = "";
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("processPath")] public string? ProcessPath { get; set; }
    [JsonPropertyName("processSha256")] public string? ProcessSha256 { get; set; }
    [JsonPropertyName("processSigned")] public bool? ProcessSigned { get; set; }
    [JsonPropertyName("processSigner")] public string? ProcessSigner { get; set; }
    [JsonPropertyName("processStartTime")] public DateTimeOffset? ProcessStartTime { get; set; }
    [JsonPropertyName("parentPid")] public int? ParentPid { get; set; }
    [JsonPropertyName("parentProcessName")] public string? ParentProcessName { get; set; }
    [JsonPropertyName("parentProcessPath")] public string? ParentProcessPath { get; set; }
    [JsonPropertyName("scanTargets")] public string[] ScanTargets { get; set; } = Array.Empty<string>();
    [JsonPropertyName("filesScanned")] public int FilesScanned { get; set; }
    [JsonPropertyName("findings")] public FileFindingPayload[] Findings { get; set; } = Array.Empty<FileFindingPayload>();
    [JsonPropertyName("note")] public string? Note { get; set; }
    /// Pasta do jogo (Minecraft) ou script/código identificado — rótulo da liberação.
    [JsonPropertyName("context")] public string? Context { get; set; }
    /// Impressão digital do conjunto de jars/scripts; base pra liberar host de código.
    [JsonPropertyName("fingerprint")] public string? Fingerprint { get; set; }
    [JsonPropertyName("gameLogPath")] public string? GameLogPath { get; set; }
    /// Mods que escreveram no log do jogo sobre o domínio/HTTP na janela do bloqueio.
    [JsonPropertyName("logSuspects")] public LogSuspectPayload[] LogSuspects { get; set; } = Array.Empty<LogSuspectPayload>();
}

public sealed class LogSuspectPayload
{
    /// Thread ou logger como aparece no log (ex: "CraftPresence").
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("modId")] public string? ModId { get; set; }
    [JsonPropertyName("modName")] public string? ModName { get; set; }
    [JsonPropertyName("modFile")] public string? ModFile { get; set; }
    [JsonPropertyName("score")] public int Score { get; set; }
    /// Linhas exatas do log que levaram à suspeita.
    [JsonPropertyName("lines")] public string[] Lines { get; set; } = Array.Empty<string>();
}

public sealed class FileFindingPayload
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("sizeBytes")] public long SizeBytes { get; set; }
    [JsonPropertyName("lastWriteTime")] public DateTimeOffset? LastWriteTime { get; set; }
    [JsonPropertyName("modId")] public string? ModId { get; set; }
    [JsonPropertyName("modName")] public string? ModName { get; set; }
    [JsonPropertyName("modVersion")] public string? ModVersion { get; set; }
    [JsonPropertyName("indicators")] public IndicatorHitPayload[] Indicators { get; set; } = Array.Empty<IndicatorHitPayload>();
}

public sealed class IndicatorHitPayload
{
    [JsonPropertyName("label")] public string Label { get; set; } = "";
    /// Arquivo dentro do jar onde achou (jar-in-jar vira "inner.jar!/a/B.class").
    [JsonPropertyName("entry")] public string Entry { get; set; } = "";
    /// String exata como está no arquivo (ex: a URL completa do webhook).
    [JsonPropertyName("match")] public string Match { get; set; } = "";
    /// Pra indicador em base64: o texto decodificado.
    [JsonPropertyName("decoded")] public string? Decoded { get; set; }
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

public sealed class RulesStatusPayload
{
    [JsonPropertyName("lastCheckedUtc")] public DateTimeOffset? LastCheckedUtc { get; set; }
    [JsonPropertyName("lastCheckOk")] public bool LastCheckOk { get; set; }
}
