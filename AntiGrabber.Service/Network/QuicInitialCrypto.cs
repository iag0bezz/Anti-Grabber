using System.Security.Cryptography;
using System.Text;

namespace AntiGrabber.Service.Network;

/// Decifra o payload de um pacote QUIC Initial (RFC 9001 §5). As "Initial Secrets"
/// não são segredo de verdade — são derivadas de constantes públicas (o salt do
/// QUICv1) justamente pra permitir essa inspeção; não é bypass de criptografia,
/// é o próprio protocolo permitindo visibilidade nesse estágio do handshake.
///
/// Só implementa o sentido "cliente" (decifrar o que o CLIENTE mandou) — é tudo
/// que esse serviço precisa, já que só inspeciona tráfego outbound.
///
/// ponytail: só QUICv1 (RFC 9001). QUICv2 (RFC 9369, salt diferente) e versões
/// antigas do Google QUIC não são suportadas — sem derivação possível, quem chama
/// trata isso como "não deu pra decifrar" e libera o tráfego (fail-open, mesma
/// filosofia do resto do sistema).
public static class QuicInitialCrypto
{
    private static readonly byte[] InitialSaltV1 =
        Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    public readonly record struct InitialKeys(byte[] Key, byte[] Iv, byte[] Hp);

    public static InitialKeys DeriveClientInitialKeys(ReadOnlySpan<byte> destinationConnectionId)
    {
        var initialSecret = HKDF.Extract(HashAlgorithmName.SHA256, destinationConnectionId.ToArray(), InitialSaltV1);
        var clientInitialSecret = HkdfExpandLabel(initialSecret, "client in", 32);
        return new InitialKeys(
            HkdfExpandLabel(clientInitialSecret, "quic key", 16),
            HkdfExpandLabel(clientInitialSecret, "quic iv", 12),
            HkdfExpandLabel(clientInitialSecret, "quic hp", 16));
    }

    /// Remove header protection e decifra o payload de um Initial packet.
    /// pnOffset é o offset (a partir do início do pacote) onde o campo Packet
    /// Number protegido começa — quem chama já parseou first byte/version/DCID/
    /// SCID/token/length pra saber onde ele está.
    /// Retorna null se a verificação de integridade do AEAD falhar (pacote
    /// corrompido, adulterado, ou pnOffset errado) — nunca lança pra tráfego
    /// externo não confiável.
    public static byte[]? TryDecrypt(ReadOnlySpan<byte> packet, int pnOffset, InitialKeys keys)
    {
        const int SampleSize = 16;
        const int MaxPnLength = 4;
        const int TagSize = 16;

        if (pnOffset + MaxPnLength + SampleSize > packet.Length) return null;

        var sample = packet.Slice(pnOffset + MaxPnLength, SampleSize);
        var mask = AesEcbEncryptBlock(keys.Hp, sample);

        // Long header: só os 4 bits baixos do primeiro byte são protegidos.
        var firstByte = (byte)(packet[0] ^ (mask[0] & 0x0F));
        var pnLength = (firstByte & 0x03) + 1;

        if (pnOffset + pnLength + TagSize > packet.Length) return null;

        Span<byte> pnBytes = stackalloc byte[4];
        packet.Slice(pnOffset, pnLength).CopyTo(pnBytes);
        for (var i = 0; i < pnLength; i++)
            pnBytes[i] ^= mask[1 + i];

        ulong packetNumber = 0;
        for (var i = 0; i < pnLength; i++)
            packetNumber = (packetNumber << 8) | pnBytes[i];
        // Sem reconstrução completa de packet number truncado (RFC 9000 Apêndice A) —
        // só correto para os primeiros pacotes de uma conexão (valor pequeno, sem
        // ambiguidade de truncamento). É exatamente o caso de uso aqui: só olhamos
        // o Initial packet inicial de cada handshake.

        var header = new byte[pnOffset + pnLength];
        packet[..pnOffset].CopyTo(header);
        header[0] = firstByte;
        for (var i = 0; i < pnLength; i++) header[pnOffset + i] = pnBytes[i];

        var rest = packet[(pnOffset + pnLength)..];
        if (rest.Length < TagSize) return null;
        var tag = rest[^TagSize..];
        var ciphertext = rest[..^TagSize];

        Span<byte> nonce = stackalloc byte[12];
        keys.Iv.CopyTo(nonce);
        for (var i = 0; i < 8; i++)
            nonce[11 - i] ^= (byte)(packetNumber >> (i * 8));

        var plaintext = new byte[ciphertext.Length];
        using var aesGcm = new AesGcm(keys.Key, TagSize);
        try
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, header);
        }
        catch (CryptographicException)
        {
            return null;
        }

        return plaintext;
    }

    private static byte[] AesEcbEncryptBlock(byte[] key, ReadOnlySpan<byte> block16)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using var encryptor = aes.CreateEncryptor();
        var output = new byte[16];
        encryptor.TransformBlock(block16.ToArray(), 0, 16, output, 0);
        return output;
    }

    // RFC 8446 §7.1 HkdfLabel — reaproveitado pelo QUIC (RFC 9001 §5.1) com
    // contexto sempre vazio.
    private static byte[] HkdfExpandLabel(byte[] secret, string label, int length)
    {
        var fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);
        var info = new byte[2 + 1 + fullLabel.Length + 1];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)fullLabel.Length;
        fullLabel.CopyTo(info, 3);
        // último byte (comprimento do context) já fica 0 — context vazio

        var output = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, secret, output, info);
        return output;
    }
}
