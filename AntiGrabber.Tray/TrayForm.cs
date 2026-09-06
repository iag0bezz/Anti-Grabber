using System.Runtime.InteropServices;
using System.Text.Json;
using AntiGrabber.Shared;
using AntiGrabber.Tray.Models;
using Microsoft.Toolkit.Uwp.Notifications;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace AntiGrabber.Tray;

public sealed class TrayForm : Form
{
    private const string VirtualHost = "app.antigrabber.local";
    private static readonly TimeSpan RevertToActiveDelay = TimeSpan.FromMinutes(2);

    private readonly WebView2 _webView = new();
    private readonly NotifyIcon _trayIcon = new();
    private readonly Store _store = new();
    private readonly TrayPipeConnection _pipe = new();
    private readonly Dictionary<string, Icon> _badgeCache = new();
    private readonly System.Windows.Forms.Timer _revertTimer = new() { Interval = (int)RevertToActiveDelay.TotalMilliseconds };
    private readonly System.Windows.Forms.Timer _updateCheckTimer = new() { Interval = (int)TimeSpan.FromHours(6).TotalMilliseconds };
    private readonly UpdateService _updates;

    private Bridge? _bridge;
    private string _trayState = "idle";
    private int _unseenBlockCount;
    private ServiceStatusPayload? _lastStatus;
    private RuleEntryPayload[]? _lastRules;

    public TrayForm()
    {
        Text = "AntiGrabber";
        FormBorderStyle = FormBorderStyle.None;
        Width = 920;
        Height = 600;
        MinimumSize = new Size(760, 460);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.White;

        _webView.Dock = DockStyle.Fill;
        Controls.Add(_webView);

        _revertTimer.Tick += (_, _) => { _revertTimer.Stop(); SetTrayState("active"); };

        _updates = new UpdateService(_store, (channel, payload) => RunOnUi(() => _bridge?.Send(channel, payload)));
        _updateCheckTimer.Tick += async (_, _) => await _updates.CheckAsync();

        SetupTrayMenu();
        RefreshTrayIcon();

        Load += async (_, _) => await InitAsync();
        FormClosing += OnFormClosing;
        VisibleChanged += (_, _) => { if (Visible && _unseenBlockCount > 0) { _unseenBlockCount = 0; RefreshTrayIcon(); } };
    }

    private void SetupTrayMenu()
    {
        var lang = _store.GetSettings().Language;
        var menu = new ContextMenuStrip();
        menu.Items.Add(HostStrings.T(lang, "menu.open"), null, (_, _) => ShowMainWindow());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(HostStrings.T(lang, "menu.quit"), null, (_, _) =>
        {
            _trayIcon.Visible = false;
            Application.Exit();
        });
        _trayIcon.ContextMenuStrip = menu;
        _trayIcon.DoubleClick -= OnTrayDoubleClick;
        _trayIcon.DoubleClick += OnTrayDoubleClick;
        _trayIcon.Visible = true;
    }

    private void OnTrayDoubleClick(object? sender, EventArgs e) => ShowMainWindow();

    private void ShowMainWindow()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (e.CloseReason != CloseReason.UserClosing) return;
        e.Cancel = true;
        Hide();
    }

    private async Task InitAsync()
    {
        var userDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AntiGrabber", "Tray", "WebView2");
        Directory.CreateDirectory(userDataFolder);

        var env = await CoreWebView2Environment.CreateAsync(userDataFolder: userDataFolder);
        await _webView.EnsureCoreWebView2Async(env);

        var webRoot = ResolveWebRoot();
        _webView.CoreWebView2.SetVirtualHostNameToFolderMapping(
            VirtualHost, webRoot, CoreWebView2HostResourceAccessKind.Allow);

        _bridge = new Bridge(_webView.CoreWebView2);
        RegisterHandlers(_bridge);

        // A página pode terminar de carregar antes ou depois do pipe conectar — sem
        // replay no bridge, um push que chegue cedo demais se perde (nenhum listener
        // registrado ainda). Reenvia o status atual sempre que a navegação conclui,
        // mesma solução que o main.js original usava no evento did-finish-load.
        _webView.CoreWebView2.NavigationCompleted += (_, e) =>
        {
            if (e.IsSuccess)
            {
                _bridge?.Send("connection-status", new { connected = _pipe.IsConnected });
                if (_lastStatus is { } status) _bridge?.Send("status", status);
                if (_lastRules is { } rules) _bridge?.Send("rules-snapshot", rules);
            }
            if (Environment.GetEnvironmentVariable("AG_DEBUG_SHOW") is not null)
                DebugLog($"NavigationCompleted success={e.IsSuccess} status={e.WebErrorStatus}");
        };

        if (Environment.GetEnvironmentVariable("AG_DEBUG_SHOW") is not null)
        {
            _webView.CoreWebView2.OpenDevToolsWindow();
        }

        _webView.CoreWebView2.Navigate($"https://{VirtualHost}/index.html");

        ToastNotificationManagerCompat.OnActivated += OnToastActivated;

        _pipe.ConnectionChanged += OnPipeConnectionChanged;
        _pipe.MessageReceived += OnPipeMessage;
        _pipe.Start();

        _updateCheckTimer.Start();
        _ = _updates.CheckAsync();
    }

    private void OnToastActivated(ToastNotificationActivatedEventArgsCompat e)
    {
        var args = ToastArguments.Parse(e.Argument);
        var eventId = args.Contains("eventId") ? args["eventId"] : null;
        RunOnUi(() =>
        {
            ShowMainWindow();
            if (eventId is not null) _bridge?.Send("open-event-detail", eventId);
        });
    }

    private void ShowBlockNotification(StoredBlockEvent ev)
    {
        var settings = _store.GetSettings();
        if (!settings.NotificationsEnabled || settings.IsNotificationsSnoozed()) return;

        var lang = settings.Language;
        var vars = new Dictionary<string, string> { ["process"] = ev.ProcessName, ["domain"] = ev.Domain };
        var message = HostStrings.T(lang, ev.CorrelatedFileAccess ? "blockMsg.correlated" : "blockMsg.suspicious", vars);

        var builder = new ToastContentBuilder()
            .AddText(HostStrings.T(lang, "notif.title"))
            .AddText(message)
            .AddArgument("eventId", ev.Id);

        if (ev.CorrelatedFileAccess) builder.AddText(HostStrings.T(lang, "notif.correlatedNote"));

        try
        {
            builder.Show();
        }
        catch (Exception ex)
        {
            DebugLog("toast Show() falhou: " + ex.Message);
        }
    }

    private void OnPipeConnectionChanged(bool connected)
    {
        RunOnUi(() =>
        {
            _bridge?.Send("connection-status", new { connected });
            if (!connected) SetTrayState("idle");
        });
    }

    private void OnPipeMessage(IpcEnvelope envelope)
    {
        RunOnUi(() =>
        {
            switch (envelope.Type)
            {
                case IpcMessageType.Status:
                    _lastStatus = envelope.Status;
                    _bridge?.Send("status", envelope.Status);
                    SetTrayState(envelope.Status?.State == "recentBlock" ? "block" : "active");
                    break;

                case IpcMessageType.RulesSnapshot:
                    _lastRules = envelope.RulesSnapshot?.Rules ?? Array.Empty<RuleEntryPayload>();
                    _bridge?.Send("rules-snapshot", _lastRules);
                    break;

                case IpcMessageType.BlockEvent when envelope.BlockEvent is { } payload:
                    var id = $"{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{Guid.NewGuid():N}"[..24];
                    var stored = _store.AddEvent(StoredBlockEvent.FromPayload(payload, id));
                    _bridge?.Send("block-event", stored);
                    if (!Visible) _unseenBlockCount++;
                    SetTrayState("block");
                    _revertTimer.Stop();
                    _revertTimer.Start();
                    ShowBlockNotification(stored);
                    break;
            }
        });
    }

    private void SetTrayState(string state)
    {
        _trayState = state;
        RefreshTrayIcon();
    }

    private void RefreshTrayIcon()
    {
        var lang = _store.GetSettings().Language;
        _trayIcon.Icon = GetBadgedIcon(_trayState, _unseenBlockCount);
        var tooltipKey = _trayState switch { "active" => "tray.active", "block" => "tray.block", _ => "tray.idle" };
        var tooltip = HostStrings.T(lang, tooltipKey) + (_unseenBlockCount > 0 ? HostStrings.UnseenSuffix(lang, _unseenBlockCount) : "");
        _trayIcon.Text = tooltip.Length > 63 ? tooltip[..63] : tooltip;
    }

    private Icon GetBadgedIcon(string state, int count)
    {
        var fileName = state switch { "active" => "tray-active.ico", "block" => "tray-block.ico", _ => "tray-idle.ico" };
        if (count <= 0) return LoadIcon(fileName);

        var label = count > 9 ? "9+" : count.ToString();
        var key = $"{state}:{label}";
        if (_badgeCache.TryGetValue(key, out var cached)) return cached;

        using var baseIcon = LoadIcon(fileName);
        using var bmp = baseIcon.ToBitmap();
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAlias;
            var d = bmp.Width * 0.62f;
            var badgeRect = new RectangleF(bmp.Width - d + bmp.Width * 0.04f, -bmp.Height * 0.06f, d, d);
            using var badgeBrush = new SolidBrush(Color.FromArgb(214, 58, 58));
            g.FillEllipse(badgeBrush, badgeRect);
            using var pen = new Pen(Color.White, Math.Max(1f, bmp.Width * 0.05f));
            g.DrawEllipse(pen, badgeRect);
            using var font = new Font("Segoe UI", bmp.Height * 0.34f, FontStyle.Bold, GraphicsUnit.Pixel);
            using var textBrush = new SolidBrush(Color.White);
            var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString(label, font, textBrush, badgeRect, sf);
        }

        var hicon = bmp.GetHicon();
        var icon = (Icon)Icon.FromHandle(hicon).Clone();
        DestroyIcon(hicon);
        _badgeCache[key] = icon;
        return icon;
    }

    private void RegisterHandlers(Bridge bridge)
    {
        bridge.On("begin-drag", _ => { BeginWindowDrag(); return Task.FromResult<object?>(null); });
        bridge.On("window-minimize", _ => { Hide(); return Task.FromResult<object?>(null); });
        bridge.On("window-close", _ => { Hide(); return Task.FromResult<object?>(null); });

        bridge.On("is-connected", _ => Task.FromResult<object?>(_pipe.IsConnected));

        bridge.On("get-app-version", _ => Task.FromResult<object?>(UpdateService.GetAppVersion()));

        bridge.On("get-events", args => Task.FromResult<object?>(_store.QueryEvents(ParseEventQuery(args))));
        bridge.On("get-event", args =>
            Task.FromResult<object?>(_store.GetEvent(args.ValueKind == JsonValueKind.String ? args.GetString() ?? "" : "")));

        bridge.On("clear-history", _ => { _store.ClearEvents(); return Task.FromResult<object?>(true); });

        bridge.On("get-settings", _ => Task.FromResult<object?>(_store.GetSettings()));
        bridge.On("update-settings", args =>
        {
            var updated = _store.UpdateSettings(s => ApplySettingsPatch(s, args));
            if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty("language", out _))
            {
                SetupTrayMenu();
                RefreshTrayIcon();
            }
            return Task.FromResult<object?>(updated);
        });

        bridge.On("export-history", _ =>
        {
            var events = _store.GetAllEvents();
            if (events.Count == 0) return Task.FromResult<object?>(new { ok = false, reason = "empty" });

            var lang = _store.GetSettings().Language;
            using var dialog = new SaveFileDialog
            {
                Title = HostStrings.T(lang, "export.dialogTitle"),
                FileName = $"antigrabber-historico-{DateTime.Now:yyyy-MM-dd}.json",
                Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv",
            };
            if (dialog.ShowDialog(this) != DialogResult.OK)
                return Task.FromResult<object?>(new { ok = false, reason = "canceled" });

            var content = dialog.FileName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
                ? EventsToCsv(events)
                : JsonSerializer.Serialize(events, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dialog.FileName, content);
            return Task.FromResult<object?>(new { ok = true, filePath = dialog.FileName });
        });

        bridge.On("open-logs-folder", _ =>
        {
            var logsDir = Path.Combine(Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData", "AntiGrabber", "logs");
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(logsDir) { UseShellExecute = true }); }
            catch { }
            return Task.FromResult<object?>(true);
        });

        bridge.On("check-for-update-now", args => { var t = _updates.CheckAsync(); return Task.FromResult<object?>(true); });

        bridge.On("start-update", args =>
        {
            var t = _updates.ApplyAsync();
            return Task.FromResult<object?>(true);
        });

        bridge.On("skip-update-version", args =>
        {
            var version = args.ValueKind == JsonValueKind.String ? args.GetString() : null;
            var updated = _store.UpdateSettings(s => s.SkippedVersion = version);
            return Task.FromResult<object?>(updated);
        });

        bridge.On("allow-always", async args =>
        {
            var (domain, processName) = ReadDomainProcess(args);
            return await _pipe.SendAsync(new IpcEnvelope
            {
                Type = IpcMessageType.AllowAlwaysCommand,
                AllowAlways = new AllowAlwaysPayload { Domain = domain, ProcessName = processName },
            });
        });

        bridge.On("remove-rule", async args =>
        {
            var (domain, processName) = ReadDomainProcess(args);
            return await _pipe.SendAsync(new IpcEnvelope
            {
                Type = IpcMessageType.RemoveRuleCommand,
                RemoveRule = new AllowAlwaysPayload { Domain = domain, ProcessName = processName },
            });
        });

        bridge.On("set-rule-enabled", async args =>
        {
            var (domain, processName) = ReadDomainProcess(args);
            var enabled = args.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True;
            return await _pipe.SendAsync(new IpcEnvelope
            {
                Type = IpcMessageType.SetRuleEnabledCommand,
                SetRuleEnabled = new SetRuleEnabledPayload { Domain = domain, ProcessName = processName, Enabled = enabled },
            });
        });
    }

    private static (string domain, string processName) ReadDomainProcess(JsonElement args)
    {
        var domain = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("domain", out var d) ? d.GetString() ?? "" : "";
        var processName = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("processName", out var p) ? p.GetString() ?? "" : "";
        return (domain, processName);
    }

    private static EventQuery ParseEventQuery(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object) return new EventQuery();
        return new EventQuery(
            Page: args.TryGetProperty("page", out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 1,
            PageSize: args.TryGetProperty("pageSize", out var ps) && ps.ValueKind == JsonValueKind.Number ? ps.GetInt32() : 20,
            Search: args.TryGetProperty("search", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null,
            CorrelatedOnly: args.TryGetProperty("correlatedOnly", out var co) && co.ValueKind == JsonValueKind.True,
            SinceDays: args.TryGetProperty("sinceDays", out var sd) && sd.ValueKind == JsonValueKind.Number ? sd.GetInt32() : null);
    }

    private static string EventsToCsv(IReadOnlyList<StoredBlockEvent> events)
    {
        static string Escape(object? v) => $"\"{(v?.ToString() ?? "").Replace("\"", "\"\"")}\"";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("timestamp,processName,domain,correlatedFileAccess,correlatedFilePath,pid,localPort,plainLanguageMessage");
        foreach (var ev in events)
        {
            sb.Append(Escape(ev.Timestamp)).Append(',')
              .Append(Escape(ev.ProcessName)).Append(',')
              .Append(Escape(ev.Domain)).Append(',')
              .Append(Escape(ev.CorrelatedFileAccess)).Append(',')
              .Append(Escape(ev.CorrelatedFilePath)).Append(',')
              .Append(Escape(ev.Pid)).Append(',')
              .Append(Escape(ev.LocalPort)).Append(',')
              .Append(Escape(ev.PlainLanguageMessage)).Append("\r\n");
        }
        return sb.ToString();
    }

    private static void ApplySettingsPatch(AppSettings s, JsonElement patch)
    {
        if (patch.ValueKind != JsonValueKind.Object) return;
        if (patch.TryGetProperty("persistHistory", out var ph)) s.PersistHistory = ph.GetBoolean();
        if (patch.TryGetProperty("notificationsEnabled", out var ne)) s.NotificationsEnabled = ne.GetBoolean();
        if (patch.TryGetProperty("notificationsSnoozedUntil", out var nsu)) s.NotificationsSnoozedUntil = nsu.Clone();
        if (patch.TryGetProperty("language", out var lang) && lang.ValueKind == JsonValueKind.String) s.Language = lang.GetString()!;
        if (patch.TryGetProperty("lastUpdateCheck", out var luc)) s.LastUpdateCheck = luc.ValueKind == JsonValueKind.Null ? null : luc.GetInt64();
        if (patch.TryGetProperty("skippedVersion", out var sv)) s.SkippedVersion = sv.ValueKind == JsonValueKind.Null ? null : sv.GetString();
        if (patch.TryGetProperty("muteWhenFullscreen", out var mf)) s.MuteWhenFullscreen = mf.GetBoolean();
        if (patch.TryGetProperty("updateChannel", out var uc) && uc.ValueKind == JsonValueKind.String) s.UpdateChannel = uc.GetString()!;
    }

    private void RunOnUi(Action action)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { try { Invoke(action); } catch (ObjectDisposedException) { } catch (InvalidOperationException) { } }
        else action();
    }

    [DllImport("user32.dll")] private static extern bool ReleaseCapture();
    [DllImport("user32.dll")] private static extern int SendMessage(IntPtr hWnd, int msg, int wParam, int lParam);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr handle);
    private const int WM_NCLBUTTONDOWN = 0xA1;
    private const int HTCAPTION = 0x2;

    private void BeginWindowDrag()
    {
        if (InvokeRequired) { Invoke(BeginWindowDrag); return; }
        ReleaseCapture();
        SendMessage(Handle, WM_NCLBUTTONDOWN, HTCAPTION, 0);
    }

    private static void DebugLog(string line)
    {
        var path = Path.Combine(Path.GetTempPath(), "ag-tray-debug.log");
        File.AppendAllText(path, $"{DateTime.Now:O} {line}{Environment.NewLine}");
    }

    private static Icon LoadIcon(string fileName) => new(Path.Combine(ResolveAssetsRoot(), fileName));

    private static string ResolveAssetsRoot() => ResolveRoot("assets", Path.Combine("tray-ui", "assets"));

    private static string ResolveWebRoot() => ResolveRoot("web", Path.Combine("tray-ui", "src", "renderer"));

    private static string ResolveRoot(string packagedSubfolder, string devRelativePath)
    {
        var packaged = Path.Combine(AppContext.BaseDirectory, packagedSubfolder);
        if (Directory.Exists(packaged)) return packaged;

        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(dir, devRelativePath);
            if (Directory.Exists(candidate)) return candidate;
            var parent = Path.GetFullPath(Path.Combine(dir, ".."));
            if (parent == dir) break;
            dir = parent;
        }

        throw new DirectoryNotFoundException(
            $"Não encontrei '{packagedSubfolder}' empacotado nem '{devRelativePath}' em dev.");
    }

    protected override async void OnFormClosed(FormClosedEventArgs e)
    {
        base.OnFormClosed(e);
        await _pipe.DisposeAsync();
    }
}
