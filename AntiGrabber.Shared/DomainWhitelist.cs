using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiGrabber.Shared;

public sealed record WhitelistEntry(
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("allowedProcessNames")] string[] AllowedProcessNames);

public sealed class DomainWhitelistStore
{
    private readonly object _lock = new();
    private Dictionary<string, HashSet<string>> _catalogEntries = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, HashSet<string>> _ruleEntries = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _filePath;

    public DomainWhitelistStore(string filePath)
    {
        _filePath = filePath;
        Load();
    }

    public void Load()
    {
        lock (_lock)
        {
            _ruleEntries = new(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(_filePath)) return;

            var json = File.ReadAllText(_filePath);
            var entries = JsonSerializer.Deserialize<List<WhitelistEntry>>(json) ?? new();
            foreach (var entry in entries)
            {
                AddInternal(_ruleEntries, entry.Domain, entry.AllowedProcessNames);
            }
        }
    }

    public void Save()
    {
        lock (_lock)
        {
            var entries = _ruleEntries
                .Select(kv => new WhitelistEntry(kv.Key, kv.Value.ToArray()))
                .ToList();
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_filePath, json);
        }
    }

    public void SeedFromCatalog(IEnumerable<AppInstallInfo> installs)
    {
        lock (_lock)
        {
            _catalogEntries = new(StringComparer.OrdinalIgnoreCase);
            foreach (var app in installs)
            {
                foreach (var domain in app.AllowedDomains)
                {
                    AddInternal(_catalogEntries, domain, app.ProcessNames);
                }
            }
        }
    }

    public void AllowAlways(string domain, string processName)
    {
        lock (_lock)
        {
            AddInternal(_ruleEntries, domain, new[] { processName });
        }
        Save();
    }

    public void MergeDownloadedRules(IEnumerable<WhitelistEntry> entries)
    {
        lock (_lock)
        {
            foreach (var entry in entries)
                AddInternal(_ruleEntries, entry.Domain, entry.AllowedProcessNames);
        }
        Save();
    }

    public bool IsAllowed(string domain, string processName)
    {
        lock (_lock)
        {
            domain = StripPort(domain);
            foreach (var dict in new[] { _catalogEntries, _ruleEntries })
            {
                foreach (var (knownDomain, processes) in dict)
                {
                    if (!MatchesDomain(domain, knownDomain)) continue;
                    if (processes.Contains(processName, StringComparer.OrdinalIgnoreCase)) return true;
                }
            }
            return false;
        }
    }

    public bool IsSensitiveDomain(string domain)
    {
        lock (_lock)
        {
            domain = StripPort(domain);
            return _catalogEntries.Keys.Any(known => MatchesDomain(domain, known))
                || _ruleEntries.Keys.Any(known => MatchesDomain(domain, known));
        }
    }

    private static bool MatchesDomain(string domain, string knownDomain)
        => domain.Equals(knownDomain, StringComparison.OrdinalIgnoreCase)
           || domain.EndsWith("." + knownDomain, StringComparison.OrdinalIgnoreCase);

    private static string StripPort(string domain)
    {
        var idx = domain.IndexOf(':');
        return idx < 0 ? domain : domain[..idx];
    }

    private static void AddInternal(Dictionary<string, HashSet<string>> dict, string domain, IEnumerable<string> processNames)
    {
        if (!dict.TryGetValue(domain, out var set))
        {
            set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            dict[domain] = set;
        }
        foreach (var p in processNames) set.Add(p);
    }
}
