namespace AntiGrabber.Service.Rules;

public sealed class RuleUpdateOptions
{
    public string RulesUrl { get; set; } = "";
    public string SignatureUrl { get; set; } = "";
    public string PublicKeyPem { get; set; } = "";
    public int PollIntervalMinutes { get; set; } = 360;
}
