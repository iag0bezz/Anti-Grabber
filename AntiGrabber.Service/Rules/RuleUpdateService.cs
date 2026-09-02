using System.Security.Cryptography;
using System.Text.Json;
using AntiGrabber.Shared;
using Microsoft.Extensions.Options;

namespace AntiGrabber.Service.Rules;

public sealed class RuleUpdateService : BackgroundService
{
    private readonly ILogger<RuleUpdateService> _logger;
    private readonly DomainWhitelistStore _whitelist;
    private readonly RuleUpdateOptions _options;
    private readonly HttpClient _http = new();

    public RuleUpdateService(ILogger<RuleUpdateService> logger, DomainWhitelistStore whitelist, IOptions<RuleUpdateOptions> options)
    {
        _logger = logger;
        _whitelist = whitelist;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_options.RulesUrl))
        {
            _logger.LogInformation("RuleUpdate:RulesUrl não configurado — canal de regras públicas desativado.");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndMergeAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao atualizar regras públicas.");
            }

            await Task.Delay(TimeSpan.FromMinutes(Math.Max(5, _options.PollIntervalMinutes)), stoppingToken);
        }
    }

    private async Task FetchAndMergeAsync(CancellationToken ct)
    {
        var rulesBytes = await _http.GetByteArrayAsync(_options.RulesUrl, ct);
        var signatureBase64 = (await _http.GetStringAsync(_options.SignatureUrl, ct)).Trim();

        if (!VerifySignature(rulesBytes, signatureBase64))
        {
            _logger.LogWarning("Assinatura das regras públicas inválida — atualização ignorada.");
            return;
        }

        var entries = JsonSerializer.Deserialize<List<WhitelistEntry>>(rulesBytes) ?? new();
        _whitelist.MergeDownloadedRules(entries);
        _logger.LogInformation("Regras públicas atualizadas: {Count} entradas.", entries.Count);
    }

    private bool VerifySignature(byte[] data, string signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(_options.PublicKeyPem)) return false;

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(_options.PublicKeyPem);
            var signature = Convert.FromBase64String(signatureBase64);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }
}
