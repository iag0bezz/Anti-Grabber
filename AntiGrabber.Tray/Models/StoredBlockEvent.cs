using System.Text.Json.Serialization;
using AntiGrabber.Shared;

namespace AntiGrabber.Tray.Models;

public sealed class StoredBlockEvent
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("timestamp")] public DateTimeOffset Timestamp { get; set; }
    [JsonPropertyName("processName")] public string ProcessName { get; set; } = "";
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("plainLanguageMessage")] public string PlainLanguageMessage { get; set; } = "";
    [JsonPropertyName("correlatedFileAccess")] public bool CorrelatedFileAccess { get; set; }
    [JsonPropertyName("pid")] public int? Pid { get; set; }
    [JsonPropertyName("localPort")] public int LocalPort { get; set; }
    [JsonPropertyName("correlatedFilePath")] public string? CorrelatedFilePath { get; set; }

    public static StoredBlockEvent FromPayload(BlockEventPayload p, string id) => new()
    {
        Id = id,
        Timestamp = p.Timestamp,
        ProcessName = p.ProcessName,
        Domain = p.Domain,
        PlainLanguageMessage = p.PlainLanguageMessage,
        CorrelatedFileAccess = p.CorrelatedFileAccess,
        Pid = p.Pid,
        LocalPort = p.LocalPort,
        CorrelatedFilePath = p.CorrelatedFilePath,
    };
}
