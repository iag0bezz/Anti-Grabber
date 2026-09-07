namespace AntiGrabber.Service.Rules;

/// Ponte entre o pedido "Revalidar regras" (vindo da Tray via IPC) e o loop de
/// polling do RuleUpdateService. Só precisa acordar o loop mais cedo — não
/// empilha pedidos: 3 cliques seguidos viram 1 verificação extra, não 3.
public sealed class RuleRevalidationSignal
{
    private readonly SemaphoreSlim _signal = new(0, 1);

    public void Request()
    {
        try { _signal.Release(); }
        catch (SemaphoreFullException) { /* já tem um pedido pendente — ignora */ }
    }

    public Task WaitAsync(CancellationToken ct) => _signal.WaitAsync(ct);
}
