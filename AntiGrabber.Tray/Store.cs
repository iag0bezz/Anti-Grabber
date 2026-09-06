using System.Text.Json;
using AntiGrabber.Tray.Models;

namespace AntiGrabber.Tray;

public sealed record EventQuery(
    int Page = 1,
    int PageSize = 20,
    string? Search = null,
    bool CorrelatedOnly = false,
    int? SinceDays = null);

public sealed record EventQueryResult(
    IReadOnlyList<StoredBlockEvent> Items,
    int Total,
    int Page,
    int PageSize,
    int TotalPages);

public sealed record DailyBlockCount(string Date, int Count);
public sealed record TopCount(string Key, int Count);
public sealed record BlockStats(
    IReadOnlyList<DailyBlockCount> Daily,
    IReadOnlyList<TopCount> TopProcesses,
    IReadOnlyList<TopCount> TopDomains,
    int Total);

// Porta store.js pra C# 1:1: mesmo formato de settings.json/events.json, mesmo
// limite de 1000 eventos, engole erro de I/O em silêncio (mesmo comportamento
// do original — perder um write de settings não pode derrubar o app).
public sealed class Store
{
    private const int MaxEvents = 1000;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _settingsPath;
    private readonly string _eventsPath;
    private readonly object _lock = new();

    private AppSettings _settings;
    private List<StoredBlockEvent> _events;

    public Store()
    {
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AntiGrabber");
        Directory.CreateDirectory(dataDir);
        _settingsPath = Path.Combine(dataDir, "settings.json");
        _eventsPath = Path.Combine(dataDir, "events.json");

        _settings = LoadSettings();
        _events = _settings.PersistHistory ? LoadEvents() : new List<StoredBlockEvent>();
    }

    private AppSettings LoadSettings()
    {
        try
        {
            var json = File.ReadAllText(_settingsPath);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    private void SaveSettings()
    {
        try
        {
            File.WriteAllText(_settingsPath, JsonSerializer.Serialize(_settings, JsonOptions));
        }
        catch
        {
        }
    }

    private List<StoredBlockEvent> LoadEvents()
    {
        try
        {
            var json = File.ReadAllText(_eventsPath);
            return JsonSerializer.Deserialize<List<StoredBlockEvent>>(json) ?? new List<StoredBlockEvent>();
        }
        catch
        {
            return new List<StoredBlockEvent>();
        }
    }

    private void SaveEvents()
    {
        if (!_settings.PersistHistory) return;
        try
        {
            var toSave = _events.Count > MaxEvents ? _events.GetRange(0, MaxEvents) : _events;
            File.WriteAllText(_eventsPath, JsonSerializer.Serialize(toSave));
        }
        catch
        {
        }
    }

    public AppSettings GetSettings()
    {
        lock (_lock) return _settings;
    }

    public AppSettings UpdateSettings(Action<AppSettings> apply)
    {
        lock (_lock)
        {
            var wasPersisting = _settings.PersistHistory;
            apply(_settings);
            SaveSettings();

            if (!_settings.PersistHistory && wasPersisting)
            {
                try { File.Delete(_eventsPath); } catch { }
            }
            return _settings;
        }
    }

    public StoredBlockEvent AddEvent(StoredBlockEvent ev)
    {
        lock (_lock)
        {
            _events.Insert(0, ev);
            if (_events.Count > MaxEvents) _events.RemoveRange(MaxEvents, _events.Count - MaxEvents);
            SaveEvents();
            return ev;
        }
    }

    public void ClearEvents()
    {
        lock (_lock)
        {
            _events.Clear();
            try { File.Delete(_eventsPath); } catch { }
        }
    }

    public StoredBlockEvent? GetEvent(string id)
    {
        lock (_lock) return _events.FirstOrDefault(e => e.Id == id);
    }

    public IReadOnlyList<StoredBlockEvent> GetAllEvents()
    {
        lock (_lock) return _events.ToList();
    }

    public EventQueryResult QueryEvents(EventQuery query)
    {
        lock (_lock)
        {
            IEnumerable<StoredBlockEvent> filtered = _events;

            if (!string.IsNullOrWhiteSpace(query.Search))
            {
                var q = query.Search.Trim().ToLowerInvariant();
                filtered = filtered.Where(e =>
                    e.Domain.ToLowerInvariant().Contains(q) ||
                    e.ProcessName.ToLowerInvariant().Contains(q));
            }
            if (query.CorrelatedOnly)
            {
                filtered = filtered.Where(e => e.CorrelatedFileAccess);
            }
            if (query.SinceDays is { } days)
            {
                var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
                filtered = filtered.Where(e => e.Timestamp >= cutoff);
            }

            var list = filtered.ToList();
            var total = list.Count;
            var pageSize = query.PageSize <= 0 ? 20 : query.PageSize;
            var totalPages = Math.Max(1, (int)Math.Ceiling(total / (double)pageSize));
            var page = Math.Min(Math.Max(1, query.Page), totalPages);
            var start = (page - 1) * pageSize;

            return new EventQueryResult(
                list.Skip(start).Take(pageSize).ToList(), total, page, pageSize, totalPages);
        }
    }

    public BlockStats GetStats(int days = 14)
    {
        lock (_lock)
        {
            var today = DateTimeOffset.UtcNow.Date;
            var daily = new List<DailyBlockCount>();
            for (var i = days - 1; i >= 0; i--)
            {
                var day = today.AddDays(-i);
                var count = _events.Count(e => e.Timestamp.UtcDateTime.Date == day);
                daily.Add(new DailyBlockCount(day.ToString("yyyy-MM-dd"), count));
            }

            var topProcesses = _events
                .GroupBy(e => e.ProcessName, StringComparer.OrdinalIgnoreCase)
                .Select(g => new TopCount(g.Key, g.Count()))
                .OrderByDescending(t => t.Count).Take(5).ToList();
            var topDomains = _events
                .GroupBy(e => e.Domain, StringComparer.OrdinalIgnoreCase)
                .Select(g => new TopCount(g.Key, g.Count()))
                .OrderByDescending(t => t.Count).Take(5).ToList();

            return new BlockStats(daily, topProcesses, topDomains, _events.Count);
        }
    }
}
