using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiGrabber.Shared;

public sealed record WhitelistEntry(
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("allowedProcessNames")] string[] AllowedProcessNames);

public sealed record AllowRule(
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("processName")] string ProcessName,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("createdAt")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("source")] string Source = "user");

internal sealed class WhitelistFile
{
    [JsonPropertyName("rules")] public List<AllowRule> Rules { get; set; } = new();
    [JsonPropertyName("sensitiveDomains")] public List<string> SensitiveDomains { get; set; } = new();
}

public sealed class DomainWhitelistStore
{
    private readonly object _lock = new();
    private Dictionary<string, HashSet<string>> _catalogEntries = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, AllowRule> _ruleEntries = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _sensitiveDomains = new(StringComparer.OrdinalIgnoreCase);
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
            _sensitiveDomains = new(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(_filePath)) return;

            try
            {
                var json = File.ReadAllText(_filePath);
                var file = JsonSerializer.Deserialize<WhitelistFile>(json);
                if (file is null) return;

                foreach (var rule in file.Rules)
                    _ruleEntries[RuleKey(rule.Domain, rule.ProcessName)] = rule;
                foreach (var domain in file.SensitiveDomains)
                    _sensitiveDomains.Add(domain);
            }
            catch (JsonException)
            {
                // arquivo corrompido ou de formato antigo incompatível — começa vazio, não derruba o serviço.
            }
        }
    }

    public void Save()
    {
        lock (_lock)
        {
            var file = new WhitelistFile
            {
                Rules = _ruleEntries.Values.ToList(),
                SensitiveDomains = _sensitiveDomains.ToList(),
            };
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(file, new JsonSerializerOptions { WriteIndented = true });
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
                    AddCatalog(domain, app.ProcessNames);
                }
            }
        }
    }

    public void AllowAlways(string domain, string processName, string source = "user")
    {
        lock (_lock)
        {
            var key = RuleKey(domain, processName);
            var createdAt = _ruleEntries.TryGetValue(key, out var existing) ? existing.CreatedAt : DateTimeOffset.UtcNow;
            _ruleEntries[key] = new AllowRule(domain, processName, true, createdAt, source);
        }
        Save();
    }

    public void RemoveRule(string domain, string processName)
    {
        lock (_lock)
        {
            _ruleEntries.Remove(RuleKey(domain, processName));
        }
        Save();
    }

    public void SetRuleEnabled(string domain, string processName, bool enabled)
    {
        lock (_lock)
        {
            var key = RuleKey(domain, processName);
            if (_ruleEntries.TryGetValue(key, out var existing))
                _ruleEntries[key] = existing with { Enabled = enabled };
        }
        Save();
    }

    public IReadOnlyList<AllowRule> GetUserRules()
    {
        lock (_lock)
        {
            return _ruleEntries.Values
                .Where(r => r.Source == "user")
                .OrderByDescending(r => r.CreatedAt)
                .ToList();
        }
    }

    public void MergeDownloadedRules(IEnumerable<WhitelistEntry> entries)
    {
        lock (_lock)
        {
            foreach (var entry in entries)
            {
                if (entry.AllowedProcessNames.Length == 0)
                {
                    _sensitiveDomains.Add(entry.Domain);
                    continue;
                }

                foreach (var processName in entry.AllowedProcessNames)
                {
                    var key = RuleKey(entry.Domain, processName);
                    var createdAt = _ruleEntries.TryGetValue(key, out var existing) ? existing.CreatedAt : DateTimeOffset.UtcNow;
                    _ruleEntries[key] = new AllowRule(entry.Domain, processName, true, createdAt, "feed");
                }
            }
        }
        Save();
    }

    public bool IsAllowed(string domain, string processName)
    {
        lock (_lock)
        {
            domain = StripPort(domain);
            foreach (var (knownDomain, processes) in _catalogEntries)
            {
                if (MatchesDomain(domain, knownDomain) && processes.Contains(processName, StringComparer.OrdinalIgnoreCase))
                    return true;
            }
            foreach (var rule in _ruleEntries.Values)
            {
                if (!rule.Enabled) continue;
                if (MatchesDomain(domain, rule.Domain) && string.Equals(rule.ProcessName, processName, StringComparison.OrdinalIgnoreCase))
                    return true;
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
                || _ruleEntries.Values.Any(r => MatchesDomain(domain, r.Domain))
                || _sensitiveDomains.Any(known => MatchesDomain(domain, known));
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

    private static string RuleKey(string domain, string processName) => $"{domain}|{processName}";

    private void AddCatalog(string domain, IEnumerable<string> processNames)
    {
        if (!_catalogEntries.TryGetValue(domain, out var set))
        {
            set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _catalogEntries[domain] = set;
        }
        foreach (var p in processNames) set.Add(p);
    }
}
