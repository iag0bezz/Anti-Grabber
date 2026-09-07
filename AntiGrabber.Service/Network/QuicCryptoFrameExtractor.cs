namespace AntiGrabber.Service.Network;

/// Extrai frames CRYPTO de dentro do payload já decifrado de um pacote QUIC Initial
/// (RFC 9000 §19.6) — é aí que o ClientHello TLS viaja, em pedaços com offset
/// explícito no stream de handshake.
///
/// ponytail: só reconhece os tipos de frame que de fato aparecem num Initial de
/// cliente (PADDING, PING, ACK, CRYPTO). Qualquer outro tipo de frame faz desistir
/// do pacote inteiro — não dá pra saber o tamanho de um frame desconhecido pra
/// pular ele com segurança sem implementar o catálogo completo de ~20 tipos do
/// RFC 9000 §19. Fail-open: quem chama trata "não deu pra extrair" como "libera
/// o tráfego sem inspecionar".
public static class QuicCryptoFrameExtractor
{
    public readonly record struct CryptoChunk(ulong Offset, byte[] Data);

    public static bool TryExtract(ReadOnlySpan<byte> payload, out List<CryptoChunk> chunks)
    {
        chunks = new List<CryptoChunk>();
        var pos = 0;

        while (pos < payload.Length)
        {
            if (payload[pos] == 0x00) { pos += 1; continue; } // PADDING (1 byte, sem corpo)

            if (!QuicVarInt.TryRead(payload[pos..], out var frameType, out var typeSize)) return false;

            if (frameType == 0x01) { pos += typeSize; continue; } // PING, sem corpo

            if (frameType == 0x02 || frameType == 0x03) // ACK / ACK com contadores ECN
            {
                pos += typeSize;
                if (!TrySkipAck(payload, ref pos, hasEcnCounts: frameType == 0x03)) return false;
                continue;
            }

            if (frameType == 0x06) // CRYPTO
            {
                pos += typeSize;
                if (!QuicVarInt.TryRead(payload[pos..], out var offset, out var offsetSize)) return false;
                pos += offsetSize;
                if (!QuicVarInt.TryRead(payload[pos..], out var length, out var lengthSize)) return false;
                pos += lengthSize;
                if (length > (ulong)(payload.Length - pos)) return false;

                chunks.Add(new CryptoChunk(offset, payload.Slice(pos, (int)length).ToArray()));
                pos += (int)length;
                continue;
            }

            // Frame de tipo não reconhecido — sem tamanho conhecido, não dá pra pular. Desiste.
            return false;
        }

        return true;
    }

    private static bool TrySkipAck(ReadOnlySpan<byte> payload, ref int pos, bool hasEcnCounts)
    {
        if (!TrySkipVarInt(payload, ref pos)) return false; // Largest Acknowledged
        if (!TrySkipVarInt(payload, ref pos)) return false; // ACK Delay
        if (!QuicVarInt.TryRead(payload[pos..], out var rangeCount, out var rangeCountSize)) return false;
        pos += rangeCountSize;
        if (!TrySkipVarInt(payload, ref pos)) return false; // First ACK Range

        for (ulong i = 0; i < rangeCount; i++)
        {
            if (!TrySkipVarInt(payload, ref pos)) return false; // Gap
            if (!TrySkipVarInt(payload, ref pos)) return false; // ACK Range Length
        }

        if (hasEcnCounts)
        {
            if (!TrySkipVarInt(payload, ref pos)) return false; // ECT0
            if (!TrySkipVarInt(payload, ref pos)) return false; // ECT1
            if (!TrySkipVarInt(payload, ref pos)) return false; // ECN-CE
        }

        return true;
    }

    private static bool TrySkipVarInt(ReadOnlySpan<byte> payload, ref int pos)
    {
        if (!QuicVarInt.TryRead(payload[pos..], out _, out var size)) return false;
        pos += size;
        return true;
    }
}
