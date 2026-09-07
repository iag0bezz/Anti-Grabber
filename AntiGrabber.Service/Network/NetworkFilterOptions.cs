namespace AntiGrabber.Service.Network;

public sealed class NetworkFilterOptions
{
    /// Liga a inspeção de QUIC/UDP 443 (SNI via CRYPTO frame do Initial packet).
    /// Desligável sem rebuild — kill switch caso a decifragem do Initial dê problema
    /// em campo (ex: mudança de versão QUIC não suportada virando ruído nos logs).
    public bool InspectQuic { get; set; } = true;
}
