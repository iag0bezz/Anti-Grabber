namespace AntiGrabber.Service.Network;

/// Decodifica um "variable-length integer" do QUIC (RFC 9000 §16) — os 2 bits
/// mais altos do primeiro byte dizem o tamanho total (1, 2, 4 ou 8 bytes).
public static class QuicVarInt
{
    public static bool TryRead(ReadOnlySpan<byte> data, out ulong value, out int bytesConsumed)
    {
        value = 0;
        bytesConsumed = 0;
        if (data.Length == 0) return false;

        var length = 1 << (data[0] >> 6);
        if (data.Length < length) return false;

        ulong v = (ulong)(data[0] & 0x3F);
        for (var i = 1; i < length; i++)
            v = (v << 8) | data[i];

        value = v;
        bytesConsumed = length;
        return true;
    }
}

public readonly record struct QuicInitialHeader(
    byte[] DestinationConnectionId,
    byte[] SourceConnectionId,
    byte[] Token,
    int PacketNumberOffset,
    int TotalPacketLength);

/// Lê os campos do header longo de um pacote QUIC Initial (RFC 9000 §17.2.2) —
/// só o suficiente pra achar onde a criptografia (QuicInitialCrypto) precisa
/// começar a trabalhar. Reserved bits e o tamanho real do Packet Number ainda
/// estão protegidos nesse ponto (removidos só depois, dentro do decrypt) — por
/// isso esse parser nunca precisa olhar pra eles.
///
/// ponytail: só reconhece QUICv1 (version==1) e tipo Initial. 0-RTT/Handshake/
/// Retry e Version Negotiation não são suportados — cada um desses exigiria
/// segredos diferentes (ou não tem payload cifrado nenhum, caso do Retry) e
/// nenhum deles carrega o ClientHello que a gente quer achar. Quem chama trata
/// "não deu pra parsear" como "não é Initial reconhecido" e libera o tráfego.
public static class QuicLongHeaderParser
{
    private const int MaxConnectionIdLength = 20; // RFC 9000 §17.2

    public static bool TryParseInitial(ReadOnlySpan<byte> packet, out QuicInitialHeader header)
    {
        header = default;
        if (packet.Length < 7) return false;

        var firstByte = packet[0];
        if ((firstByte & 0x80) == 0) return false; // header curto, não é Initial
        if ((firstByte & 0x40) == 0) return false; // fixed bit deveria ser 1

        var packetType = (firstByte >> 4) & 0x03;
        if (packetType != 0) return false; // 0 = Initial

        var version = (uint)((packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4]);
        if (version != 1) return false; // só QUICv1 (RFC 9001)

        var pos = 5;

        if (pos >= packet.Length) return false;
        var dcidLen = packet[pos]; pos += 1;
        if (dcidLen > MaxConnectionIdLength || pos + dcidLen > packet.Length) return false;
        var dcid = packet.Slice(pos, dcidLen).ToArray();
        pos += dcidLen;

        if (pos >= packet.Length) return false;
        var scidLen = packet[pos]; pos += 1;
        if (scidLen > MaxConnectionIdLength || pos + scidLen > packet.Length) return false;
        var scid = packet.Slice(pos, scidLen).ToArray();
        pos += scidLen;

        if (!QuicVarInt.TryRead(packet[pos..], out var tokenLen, out var tokenLenSize)) return false;
        pos += tokenLenSize;
        if (tokenLen > (ulong)(packet.Length - pos)) return false;
        var token = packet.Slice(pos, (int)tokenLen).ToArray();
        pos += (int)tokenLen;

        if (!QuicVarInt.TryRead(packet[pos..], out var length, out var lengthSize)) return false;
        pos += lengthSize;
        if (length > (ulong)(packet.Length - pos)) return false;

        header = new QuicInitialHeader(dcid, scid, token, pos, pos + (int)length);
        return true;
    }
}
