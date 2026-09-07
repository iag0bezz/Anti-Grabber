namespace AntiGrabber.Service.Network;

public enum ClientHelloParseStatus
{
    /// SNI extraído (ou ClientHello sem extensão server_name — sni fica null nesse caso).
    Complete,

    /// Bytes disponíveis não cobrem o record/handshake declarado — precisa de mais dados
    /// (ClientHello fragmentado em múltiplos segmentos TCP).
    Incomplete,

    /// Não é um ClientHello válido (tamanho declarado impossível, handshake corrompido,
    /// ou mensagem de handshake que cruza mais de um record TLS — caso raro, não suportado).
    Invalid,
}

public static class TlsSniParser
{
    // RFC 8446 §5.1 — um record TLS nunca excede 2^14 bytes.
    private const int MaxTlsRecordLength = 16384;

    public static ClientHelloParseStatus TryExtractSni(ReadOnlySpan<byte> tcpPayload, out string? sni)
    {
        try
        {
            return ExtractCore(tcpPayload, out sni);
        }
        catch
        {
            sni = null;
            return ClientHelloParseStatus.Invalid;
        }
    }

    private static ClientHelloParseStatus ExtractCore(ReadOnlySpan<byte> data, out string? sni)
    {
        sni = null;

        if (data.Length < 5) return ClientHelloParseStatus.Incomplete;
        if (data[0] != 0x16) return ClientHelloParseStatus.Invalid;

        var recordLength = ReadUInt16(data, 3);
        if (recordLength == 0 || recordLength > MaxTlsRecordLength) return ClientHelloParseStatus.Invalid;
        if (data.Length < 5 + recordLength) return ClientHelloParseStatus.Incomplete;

        var handshake = data.Slice(5, recordLength);
        if (handshake.Length < 4 || handshake[0] != 0x01) return ClientHelloParseStatus.Invalid;

        var bodyLen = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
        if (4 + bodyLen > handshake.Length)
        {
            // Mensagem de handshake maior que este record (cruzaria pra outro record TLS).
            // Caso legítimo raríssimo para ClientHello — não vale a complexidade de suportar.
            return ClientHelloParseStatus.Invalid;
        }

        return ParseClientHelloBody(handshake.Slice(4, bodyLen), out sni);
    }

    private static ClientHelloParseStatus ParseClientHelloBody(ReadOnlySpan<byte> body, out string? sni)
    {
        sni = null;
        var pos = 2; // client_version
        if (pos + 32 > body.Length) return ClientHelloParseStatus.Invalid;
        pos += 32; // random

        if (pos >= body.Length) return ClientHelloParseStatus.Invalid;
        var sessionIdLen = body[pos]; pos += 1 + sessionIdLen;

        if (pos + 2 > body.Length) return ClientHelloParseStatus.Invalid;
        var cipherSuitesLen = ReadUInt16(body, pos); pos += 2 + cipherSuitesLen;

        if (pos >= body.Length) return ClientHelloParseStatus.Invalid;
        var compressionLen = body[pos]; pos += 1 + compressionLen;

        if (pos == body.Length)
        {
            // ClientHello sem bloco de extensions (legado) — não tem como carregar SNI.
            return ClientHelloParseStatus.Complete;
        }

        if (pos + 2 > body.Length) return ClientHelloParseStatus.Invalid;
        var extensionsLen = ReadUInt16(body, pos); pos += 2;
        var extensionsEnd = pos + extensionsLen;
        if (extensionsEnd > body.Length) return ClientHelloParseStatus.Invalid;

        while (pos + 4 <= extensionsEnd)
        {
            var extType = ReadUInt16(body, pos);
            var extLen = ReadUInt16(body, pos + 2);
            var extStart = pos + 4;
            if (extStart + extLen > extensionsEnd) return ClientHelloParseStatus.Invalid;

            if (extType == 0x0000)
            {
                sni = ParseServerNameExtension(body.Slice(extStart, extLen));
                return ClientHelloParseStatus.Complete;
            }
            pos = extStart + extLen;
        }

        return ClientHelloParseStatus.Complete; // sem extensão server_name (ex: conexão por IP)
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
