using AntiGrabber.Shared;

namespace AntiGrabber.Tray;

// Envolve AntiGrabber.Shared.IpcClient (o cliente de pipe nomeado que já existia
// pro tray WPF original) com um loop de reconexão — IpcClient não retenta sozinho.
// Mesmo intervalo de 3s do pipeClient.js que isto substitui.
public sealed class TrayPipeConnection : IAsyncDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private IpcClient? _client;
    private Task? _loopTask;

    public event Action<bool>? ConnectionChanged;
    public event Action<IpcEnvelope>? MessageReceived;

    public bool IsConnected => _client?.IsConnected == true;

    public void Start()
    {
        _loopTask = Task.Run(() => ReconnectLoopAsync(_cts.Token));
    }

    private async Task ReconnectLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var client = new IpcClient();
            client.MessageReceived += env => MessageReceived?.Invoke(env);

            bool ok;
            try { ok = await client.TryConnectAsync(4000, ct); }
            catch (OperationCanceledException) { break; }

            if (ok)
            {
                _client = client;
                ConnectionChanged?.Invoke(true);

                try
                {
                    while (client.IsConnected && !ct.IsCancellationRequested)
                        await Task.Delay(500, ct);
                }
                catch (OperationCanceledException) { }

                _client = null;
                ConnectionChanged?.Invoke(false);
                await client.DisposeAsync();
            }

            try { await Task.Delay(3000, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    public async Task<bool> SendAsync(IpcEnvelope envelope)
    {
        if (_client is not { IsConnected: true } client) return false;
        try
        {
            await client.SendAsync(envelope, CancellationToken.None);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_loopTask is not null)
        {
            try { await _loopTask; } catch { }
        }
        if (_client is not null) await _client.DisposeAsync();
    }
}
