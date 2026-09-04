using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace AntiGrabber.Tray;

// Substitui ipcMain.handle/ipcMain.on do Electron. Um canal por chave, igual
// a lista de handlers que main.js já tinha — só que tipado e sem precisar de
// contextBridge, já que o protocolo inteiro é o webview-bridge.js do outro lado.
public sealed class Bridge
{
    private static readonly JsonSerializerOptions CaseInsensitive = new() { PropertyNameCaseInsensitive = true };

    // camelCase por padrão pra qualquer DTO que não tenha [JsonPropertyName] explícito
    // (AppSettings/StoredBlockEvent já têm e continuam corretos — atributo explícito
    // sempre vence a naming policy). Sem isso, um record simples tipo EventQueryResult
    // serializa em PascalCase e o front (que espera camelCase) recebe undefined.
    private static readonly JsonSerializerOptions OutgoingOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly Dictionary<string, Func<JsonElement, Task<object?>>> _handlers = new();
    private readonly CoreWebView2 _webView;

    public Bridge(CoreWebView2 webView)
    {
        _webView = webView;
        webView.WebMessageReceived += OnMessageReceived;
    }

    public void On(string channel, Func<JsonElement, Task<object?>> handler) => _handlers[channel] = handler;

    public void Send(string channel, object? payload) =>
        _webView.PostWebMessageAsJson(JsonSerializer.Serialize(new { channel, payload }, OutgoingOptions));

    private async void OnMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        BridgeRequest? req;
        try
        {
            req = JsonSerializer.Deserialize<BridgeRequest>(e.WebMessageAsJson, CaseInsensitive);
        }
        catch
        {
            return;
        }
        if (req is null || string.IsNullOrEmpty(req.Channel)) return;

        if (!_handlers.TryGetValue(req.Channel, out var handler))
        {
            if (req.Id is { } missingId) PostError(missingId, $"canal desconhecido: {req.Channel}");
            return;
        }

        try
        {
            var result = await handler(req.Args);
            if (req.Id is { } id) PostResult(id, result);
        }
        catch (Exception ex)
        {
            if (req.Id is { } id) PostError(id, ex.Message);
        }
    }

    private void PostResult(int id, object? result) =>
        _webView.PostWebMessageAsJson(JsonSerializer.Serialize(new { id, result }, OutgoingOptions));

    private void PostError(int id, string error) =>
        _webView.PostWebMessageAsJson(JsonSerializer.Serialize(new { id, error }, OutgoingOptions));

    private sealed class BridgeRequest
    {
        public int? Id { get; set; }
        public string Channel { get; set; } = "";
        public JsonElement Args { get; set; }
    }
}
