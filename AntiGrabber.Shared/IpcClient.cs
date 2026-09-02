using System.IO.Pipes;

namespace AntiGrabber.Shared;

public sealed class IpcClient : IAsyncDisposable
{
    private NamedPipeClientStream? _pipe;

    public event Action<IpcEnvelope>? MessageReceived;

    public async Task<bool> TryConnectAsync(int timeoutMs, CancellationToken ct)
    {
        try
        {
            _pipe = new NamedPipeClientStream(".", PipeMessageFramer.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await _pipe.ConnectAsync(timeoutMs, ct);
            _ = Task.Run(() => ReceiveLoopAsync(ct), ct);
            return true;
        }
        catch
        {
            _pipe?.Dispose();
            _pipe = null;
            return false;
        }
    }

    public bool IsConnected => _pipe?.IsConnected == true;

    public Task SendAsync(IpcEnvelope envelope, CancellationToken ct)
    {
        if (_pipe is null || !_pipe.IsConnected) throw new InvalidOperationException("pipe não conectado");
        return PipeMessageFramer.WriteAsync(_pipe, envelope, ct);
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        try
        {
            while (_pipe is { IsConnected: true } && !ct.IsCancellationRequested)
            {
                var envelope = await PipeMessageFramer.ReadAsync(_pipe, ct);
                if (envelope is null) break;
                MessageReceived?.Invoke(envelope);
            }
        }
        catch { }
    }

    public ValueTask DisposeAsync()
    {
        _pipe?.Dispose();
        return ValueTask.CompletedTask;
    }
}
