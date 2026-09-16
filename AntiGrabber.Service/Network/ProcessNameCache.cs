using System.Collections.Concurrent;

namespace AntiGrabber.Service.Network;

/// Debounce pra falso positivo "processo desconhecido": um processo que fecha
/// entre o SYN e a resolução do PID (Process.GetProcessById falha) ainda tinha
/// nome resolvido nas conexões anteriores pro mesmo destino. Reusa esse nome
/// só pro mesmo PID + mesmo domínio — nunca herda nome pra um domínio diferente.
public sealed class ProcessNameCache
{
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(10);
    private readonly ConcurrentDictionary<(int Pid, string Domain), (DateTime When, string ProcessName)> _lastKnown = new();

    public void Record(int pid, string domain, string processName)
        => _lastKnown[(pid, domain)] = (DateTime.UtcNow, processName);

    public string? TryGetRecent(int pid, string domain)
        => _lastKnown.TryGetValue((pid, domain), out var last) && DateTime.UtcNow - last.When <= Window
            ? last.ProcessName
            : null;
}
