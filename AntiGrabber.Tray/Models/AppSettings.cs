using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiGrabber.Tray.Models;

public sealed class AppSettings
{
    [JsonPropertyName("persistHistory")] public bool PersistHistory { get; set; } = true;
    [JsonPropertyName("notificationsEnabled")] public bool NotificationsEnabled { get; set; } = true;

    // null | "indefinite" | epoch-ms number — mesma união solta do store.js original,
    // guardada crua pra não perder fidelidade no round-trip com o front.
    [JsonPropertyName("notificationsSnoozedUntil")] public JsonElement? NotificationsSnoozedUntil { get; set; }

    [JsonPropertyName("language")] public string Language { get; set; } = "pt";
    [JsonPropertyName("lastUpdateCheck")] public long? LastUpdateCheck { get; set; }
    [JsonPropertyName("skippedVersion")] public string? SkippedVersion { get; set; }
    [JsonPropertyName("muteWhenFullscreen")] public bool MuteWhenFullscreen { get; set; } = true;
    [JsonPropertyName("updateChannel")] public string UpdateChannel { get; set; } = "stable";

    public bool IsNotificationsSnoozed()
    {
        if (NotificationsSnoozedUntil is not { } v || v.ValueKind == JsonValueKind.Null) return false;
        if (v.ValueKind == JsonValueKind.String) return v.GetString() == "indefinite";
        if (v.ValueKind == JsonValueKind.Number) return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < v.GetInt64();
        return false;
    }
}
