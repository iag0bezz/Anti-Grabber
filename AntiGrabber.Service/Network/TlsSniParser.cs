namespace AntiGrabber.Service.Network;

public static class TlsSniParser
{
    public static string? TryExtractSni(ReadOnlySpan<byte> tcpPayload)
    {
        try
        {
            return ExtractCore(tcpPayload);
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractCore(ReadOnlySpan<byte> data)
    {
        if (data.Length < 5 || data[0] != 0x16) return null;

        var handshake = data[5..];
        if (handshake.Length < 4 || handshake[0] != 0x01) return null;

        var pos = 4;
        pos += 2;
        if (pos + 32 > handshake.Length) return null;
        pos += 32;

        if (pos >= handshake.Length) return null;
        var sessionIdLen = handshake[pos]; pos += 1 + sessionIdLen;

        if (pos + 2 > handshake.Length) return null;
        var cipherSuitesLen = ReadUInt16(handshake, pos); pos += 2 + cipherSuitesLen;

        if (pos >= handshake.Length) return null;
        var compressionLen = handshake[pos]; pos += 1 + compressionLen;

        if (pos + 2 > handshake.Length) return null;
        var extensionsLen = ReadUInt16(handshake, pos); pos += 2;
        var extensionsEnd = Math.Min(pos + extensionsLen, handshake.Length);

        while (pos + 4 <= extensionsEnd)
        {
            var extType = ReadUInt16(handshake, pos);
            var extLen = ReadUInt16(handshake, pos + 2);
            var extStart = pos + 4;
            if (extStart + extLen > handshake.Length) return null;

            if (extType == 0x0000)
            {
                return ParseServerNameExtension(handshake.Slice(extStart, extLen));
            }
            pos = extStart + extLen;
        }
        return null;
    }

    private static string? ParseServerNameExtension(ReadOnlySpan<byte> ext)
    {
        if (ext.Length < 2) return null;
        var listLen = ReadUInt16(ext, 0);
        var pos = 2;
        var end = Math.Min(2 + listLen, ext.Length);

        while (pos + 3 <= end)
        {
            var nameType = ext[pos];
            var nameLen = ReadUInt16(ext, pos + 1);
            var nameStart = pos + 3;
            if (nameStart + nameLen > ext.Length) return null;

            if (nameType == 0x00)
                return System.Text.Encoding.ASCII.GetString(ext.Slice(nameStart, nameLen));

            pos = nameStart + nameLen;
        }
        return null;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset)
        => (ushort)((data[offset] << 8) | data[offset + 1]);
}
