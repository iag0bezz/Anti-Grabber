using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace AntiGrabber.Shared;

public static class PipeMessageFramer
{
    public const string PipeName = "AntiGrabber.IpcPipe";
    private const int MaxMessageBytes = 64 * 1024;

    public static async Task WriteAsync(PipeStream pipe, IpcEnvelope envelope, CancellationToken ct)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(envelope);
        if (json.Length > MaxMessageBytes) throw new InvalidOperationException("mensagem IPC excede limite");
        var lengthPrefix = BitConverter.GetBytes(json.Length);
        await pipe.WriteAsync(lengthPrefix, ct);
        await pipe.WriteAsync(json, ct);
        await pipe.FlushAsync(ct);
    }

    public static async Task<IpcEnvelope?> ReadAsync(PipeStream pipe, CancellationToken ct)
    {
        var lengthPrefix = new byte[4];
        if (!await ReadExactAsync(pipe, lengthPrefix, ct)) return null;
        var length = BitConverter.ToInt32(lengthPrefix);
        if (length <= 0 || length > MaxMessageBytes) return null;

        var buffer = new byte[length];
        if (!await ReadExactAsync(pipe, buffer, ct)) return null;

        return JsonSerializer.Deserialize<IpcEnvelope>(buffer);
    }

    private static async Task<bool> ReadExactAsync(PipeStream pipe, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await pipe.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }
}
