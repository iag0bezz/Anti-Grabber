namespace AntiGrabber.Tray;

// Subconjunto de tray-ui/src/renderer/i18n.js que o HOST (não a página) precisa —
// tooltip/menu da bandeja e título da notificação. A página continua usando
// i18n.js sem mudança nenhuma; isto é só pro punhado de strings que o C# usa
// direto. Mantido em sincronia à mão — lista curta, não muda com frequência.
public static class HostStrings
{
    private static readonly Dictionary<string, Dictionary<string, string>> Dict = new()
    {
        ["pt"] = new()
        {
            ["notif.title"] = "AntiGrabber bloqueou uma tentativa",
            ["notif.program"] = "Programa: {process}",
            ["notif.domain"] = "Domínio: {domain}",
            ["notif.correlatedNote"] = "Acesso a arquivo sensível detectado logo antes",
            ["notif.updateTitle"] = "Atualização disponível",
            ["notif.updateBody"] = "AntiGrabber {version} já pode ser instalado.",
            ["blockMsg.correlated"] = "Bloqueamos uma tentativa de roubo: {process} tentou enviar dados para {domain} logo após acessar seus arquivos.",
            ["blockMsg.suspicious"] = "Bloqueamos uma conexão suspeita: {process} tentou falar com {domain} sem autorização.",
            ["tray.active"] = "AntiGrabber — protegendo",
            ["tray.block"] = "AntiGrabber — bloqueio recente",
            ["tray.idle"] = "AntiGrabber — ocioso",
            ["menu.open"] = "Abrir AntiGrabber",
            ["menu.quit"] = "Sair",
            ["export.dialogTitle"] = "Exportar histórico de bloqueios",
            ["export.configDialogTitle"] = "Exportar configuração do AntiGrabber",
            ["import.configDialogTitle"] = "Importar configuração do AntiGrabber",
        },
        ["en"] = new()
        {
            ["notif.title"] = "AntiGrabber blocked an attempt",
            ["notif.program"] = "Program: {process}",
            ["notif.domain"] = "Domain: {domain}",
            ["notif.correlatedNote"] = "Sensitive file access detected right before",
            ["notif.updateTitle"] = "Update available",
            ["notif.updateBody"] = "AntiGrabber {version} is ready to install.",
            ["blockMsg.correlated"] = "We blocked a theft attempt: {process} tried to send data to {domain} right after accessing your files.",
            ["blockMsg.suspicious"] = "We blocked a suspicious connection: {process} tried to reach {domain} without authorization.",
            ["tray.active"] = "AntiGrabber — protecting",
            ["tray.block"] = "AntiGrabber — recent block",
            ["tray.idle"] = "AntiGrabber — idle",
            ["menu.open"] = "Open AntiGrabber",
            ["menu.quit"] = "Quit",
            ["export.dialogTitle"] = "Export block history",
            ["export.configDialogTitle"] = "Export AntiGrabber configuration",
            ["import.configDialogTitle"] = "Import AntiGrabber configuration",
        },
        ["es"] = new()
        {
            ["notif.title"] = "AntiGrabber bloqueó un intento",
            ["notif.program"] = "Programa: {process}",
            ["notif.domain"] = "Dominio: {domain}",
            ["notif.correlatedNote"] = "Acceso a archivo sensible detectado justo antes",
            ["notif.updateTitle"] = "Actualización disponible",
            ["notif.updateBody"] = "AntiGrabber {version} ya se puede instalar.",
            ["blockMsg.correlated"] = "Bloqueamos un intento de robo: {process} intentó enviar datos a {domain} justo después de acceder a tus archivos.",
            ["blockMsg.suspicious"] = "Bloqueamos una conexión sospechosa: {process} intentó contactar con {domain} sin autorización.",
            ["tray.active"] = "AntiGrabber — protegiendo",
            ["tray.block"] = "AntiGrabber — bloqueo reciente",
            ["tray.idle"] = "AntiGrabber — inactivo",
            ["menu.open"] = "Abrir AntiGrabber",
            ["menu.quit"] = "Salir",
            ["export.dialogTitle"] = "Exportar historial de bloqueos",
            ["export.configDialogTitle"] = "Exportar configuración de AntiGrabber",
            ["import.configDialogTitle"] = "Importar configuración de AntiGrabber",
        },
    };

    public static string T(string? lang, string key, IReadOnlyDictionary<string, string>? vars = null)
    {
        var table = Dict.TryGetValue(lang ?? "pt", out var t) ? t : Dict["pt"];
        var value = table.TryGetValue(key, out var v) ? v : key;
        if (vars is null) return value;
        foreach (var (k, val) in vars) value = value.Replace("{" + k + "}", val);
        return value;
    }

    public static string UnseenSuffix(string? lang, int n)
    {
        return lang switch
        {
            "en" => $" ({n} unseen)",
            "es" => $" ({n} sin ver)",
            _ => $" ({n} não visto{(n == 1 ? "" : "s")})",
        };
    }
}
