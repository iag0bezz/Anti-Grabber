using System.Security.Cryptography;
using System.Text.Json;
using AntiGrabber.Service.Ipc;
using AntiGrabber.Shared;
using Microsoft.Extensions.Options;

namespace AntiGrabber.Service.Rules;

public sealed class RuleUpdateService : BackgroundService
{
    private readonly ILogger<RuleUpdateService> _logger;
    private readonly DomainWhitelistStore _whitelist;
    private readonly IpcServer _ipcServer;
    private readonly RuleRevalidationSignal _revalidationSignal;
    private readonly RuleUpdateOptions _options;
    private readonly HttpClient _http = new();

    public RuleUpdateService(
        ILogger<RuleUpdateService> logger,
        DomainWhitelistStore whitelist,
        IpcServer ipcServer,
        RuleRevalidationSignal revalidationSignal,
        IOptions<RuleUpdateOptions> options)
    {
        _logger = logger;
        _whitelist = whitelist;
        _ipcServer = ipcServer;
        _revalidationSignal = revalidationSignal;
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
            var ok = false;
            try
            {
                ok = await FetchAndMergeAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao atualizar regras públicas.");
            }

            await _ipcServer.PublishRulesStatusAsync(DateTimeOffset.UtcNow, ok);
            await WaitForNextCheckAsync(stoppingToken);
        }
    }

    // Espera pelo intervalo normal OU por um pedido manual de "Revalidar regras"
    // (vindo da Tray) — o que vier primeiro. Um pedido manual não atrapalha o
    // ciclo normal: só faz essa espera terminar mais cedo.
    private async Task WaitForNextCheckAsync(CancellationToken stoppingToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var delayTask = Task.Delay(TimeSpan.FromMinutes(Math.Max(5, _options.PollIntervalMinutes)), cts.Token);
        var signalTask = _revalidationSignal.WaitAsync(cts.Token);

        try
        {
            await Task.WhenAny(delayTask, signalTask);
        }
        finally
        {
            cts.Cancel();
            await Task.WhenAll(SwallowCancellation(delayTask), SwallowCancellation(signalTask));
        }
    }

    private static async Task SwallowCancellation(Task task)
    {
        try { await task; }
        catch (OperationCanceledException) { }
    }

    private async Task<bool> FetchAndMergeAsync(CancellationToken ct)
    {
        var rulesBytes = await _http.GetByteArrayAsync(_options.RulesUrl, ct);
        var signatureBase64 = (await _http.GetStringAsync(_options.SignatureUrl, ct)).Trim();

        if (!VerifySignature(rulesBytes, signatureBase64))
        {
            _logger.LogWarning("Assinatura das regras públicas inválida — atualização ignorada.");
            return false;
        }

        var entries = JsonSerializer.Deserialize<List<WhitelistEntry>>(rulesBytes) ?? new();
        _whitelist.MergeDownloadedRules(entries);
        _logger.LogInformation("Regras públicas atualizadas: {Count} entradas.", entries.Count);
        return true;
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
