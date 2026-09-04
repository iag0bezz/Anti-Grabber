'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { pathToFileURL } = require('node:url');
const { app, Tray, Menu, BrowserWindow, ipcMain, Notification, nativeImage, shell, dialog } = require('electron');
const { PipeClient, IpcMessageType } = require('./ipc/pipeClient');
const { Store } = require('./store');
const { translate } = require('./renderer/i18n');

const ASSETS_DIR = path.join(__dirname, '..', 'assets');
const TRAY_ICON_PATHS = {
  idle: path.join(ASSETS_DIR, 'tray-idle.ico'),
  active: path.join(ASSETS_DIR, 'tray-active.ico'),
  block: path.join(ASSETS_DIR, 'tray-block.ico'),
};
const TRAY_ICONS = {
  idle: nativeImage.createFromPath(TRAY_ICON_PATHS.idle),
  active: nativeImage.createFromPath(TRAY_ICON_PATHS.active),
  block: nativeImage.createFromPath(TRAY_ICON_PATHS.block),
};

let tray = null;
let mainWindow = null;
let pipeClient = null;
let store = null;
let revertTimer = null;
let currentTrayState = 'idle';
let unseenBlockCount = 0;
const badgeIconCache = new Map();

app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu-sandbox');

if (!app.requestSingleInstanceLock()) {
  app.quit();
}

app.on('second-instance', () => showWindow());

app.whenReady().then(() => {
  app.setAppUserModelId('com.antigrabber.tray');
  store = new Store();
  createTray();
  createWindow();
  connectToService();
  if (process.env.AG_DEBUG_SHOW) showWindow();
});

app.on('window-all-closed', (e) => e.preventDefault());

function createTray() {
  tray = new Tray(TRAY_ICONS.idle);
  setTrayState('idle');
  rebuildTrayMenu();
  tray.on('double-click', () => showWindow());
}

function rebuildTrayMenu() {
  const lang = store?.getSettings().language;
  const menu = Menu.buildFromTemplate([
    { label: translate(lang, 'menu.open'), click: () => showWindow() },
    { type: 'separator' },
    { label: translate(lang, 'menu.quit'), click: () => app.exit(0) },
  ]);
  tray.setContextMenu(menu);
}

function setTrayState(state) {
  currentTrayState = state;
  const lang = store?.getSettings().language;
  const stateKey = state === 'active' ? 'tray.active' : state === 'block' ? 'tray.block' : 'tray.idle';
  tray.setToolTip(
    translate(lang, stateKey) +
    (unseenBlockCount > 0 ? translate(lang, 'tray.unseenSuffix', { n: unseenBlockCount }) : '')
  );
  refreshTrayIcon();
}

// ponytail: composed via offscreen render (no image lib dependency); caps at "9+" and caches per state+count.
async function getBadgedTrayIcon(state, count) {
  const baseIcon = TRAY_ICONS[state] ?? TRAY_ICONS.idle;
  if (!count) return baseIcon;

  const label = count > 9 ? '9+' : String(count);
  const cacheKey = `${state}:${label}`;
  if (badgeIconCache.has(cacheKey)) return badgeIconCache.get(cacheKey);

  const fileUrl = pathToFileURL(TRAY_ICON_PATHS[state] ?? TRAY_ICON_PATHS.idle).href;
  const html = `data:text/html;charset=utf-8,${encodeURIComponent(`
    <html><body style="margin:0;width:32px;height:32px;background:transparent;overflow:hidden">
      <img src="${fileUrl}" width="32" height="32" style="display:block;position:absolute;top:0;left:0" />
      <svg width="32" height="32" style="position:absolute;top:0;left:0">
        <circle cx="24" cy="9" r="8" fill="#d63a3a" stroke="white" stroke-width="1.5"/>
        <text x="24" y="12.5" font-family="Segoe UI, sans-serif" font-size="9" font-weight="700" fill="white" text-anchor="middle">${label}</text>
      </svg>
    </body></html>`)}`;

  const offscreen = new BrowserWindow({
    show: false,
    width: 32,
    height: 32,
    frame: false,
    transparent: true,
    webPreferences: { offscreen: true },
  });

  try {
    await offscreen.loadURL(html);
    const image = await offscreen.webContents.capturePage();
    badgeIconCache.set(cacheKey, image);
    return image;
  } catch {
    return baseIcon;
  } finally {
    offscreen.destroy();
  }
}

async function refreshTrayIcon() {
  const icon = await getBadgedTrayIcon(currentTrayState, unseenBlockCount);
  if (tray) tray.setImage(icon);
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 920,
    height: 600,
    minWidth: 760,
    minHeight: 460,
    show: false,
    frame: false,
    resizable: true,
    backgroundColor: '#00000000',
    icon: path.join(ASSETS_DIR, 'app.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.webContents.on('did-finish-load', () => {
    send('connection-status', { connected: pipeClient?.connected ?? false });
  });

  if (process.env.AG_DEBUG_SHOW) {
    const dbgLog = (line) => fs.appendFileSync(path.join(require('node:os').tmpdir(), 'ag-debug.log'), line + '\n');
    mainWindow.webContents.on('console-message', (_e, level, message, line, sourceId) => {
      dbgLog(`[renderer:${level}] ${message} (${sourceId}:${line})`);
    });
    mainWindow.webContents.on('did-fail-load', (_e, code, desc, url) => {
      dbgLog(`[did-fail-load] ${code} ${desc} ${url}`);
    });
    mainWindow.webContents.on('render-process-gone', (_e, details) => dbgLog(`[render-process-gone] ${JSON.stringify(details)}`));
  }

  mainWindow.on('close', (e) => {
    e.preventDefault();
    mainWindow.hide();
  });
}

function showWindow() {
  if (!mainWindow) return;
  mainWindow.show();
  mainWindow.focus();
  if (unseenBlockCount > 0) {
    unseenBlockCount = 0;
    refreshTrayIcon();
  }
}

function connectToService() {
  pipeClient = new PipeClient();

  pipeClient.on('connected', () => {
    send('connection-status', { connected: true });
  });

  pipeClient.on('disconnected', () => {
    send('connection-status', { connected: false });
    setTrayState('idle');
  });

  pipeClient.on('message', (envelope) => {
    switch (envelope.type) {
      case IpcMessageType.Status:
        send('status', envelope.status);
        setTrayState(envelope.status?.state === 'recentBlock' ? 'block' : 'active');
        break;

      case IpcMessageType.RulesSnapshot:
        send('rules-snapshot', envelope.rulesSnapshot?.rules ?? []);
        break;

      case IpcMessageType.BlockEvent: {
        const stored = store.addEvent(envelope.blockEvent);
        send('block-event', stored);
        if (!mainWindow || !mainWindow.isVisible()) unseenBlockCount++;
        setTrayState('block');
        const settings = store.getSettings();
        if (settings.notificationsEnabled && !store.notificationsSnoozed()) showBlockNotification(stored);
        scheduleRevertToActive();
        break;
      }
    }
  });

  pipeClient.start();
}

function scheduleRevertToActive() {
  if (revertTimer) clearTimeout(revertTimer);
  revertTimer = setTimeout(() => setTrayState('active'), 2 * 60 * 1000);
}

function showBlockNotification(ev) {
  if (!ev) return;
  const lang = store?.getSettings().language;
  const vars = { process: ev.processName, domain: ev.domain };
  const message = translate(lang, ev.correlatedFileAccess ? 'blockMsg.correlated' : 'blockMsg.suspicious', vars);
  const detailLines = [
    translate(lang, 'notif.program', vars),
    translate(lang, 'notif.domain', vars),
    ev.correlatedFileAccess ? translate(lang, 'notif.correlatedNote') : null,
  ].filter(Boolean);

  const notification = new Notification({
    title: translate(lang, 'notif.title'),
    body: message + '\n' + detailLines.join(' · '),
    icon: TRAY_ICONS.block,
  });
  notification.on('click', () => {
    showWindow();
    send('open-event-detail', ev.id);
  });
  notification.show();
}

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

ipcMain.handle('allow-always', async (_event, { domain, processName }) => {
  return pipeClient?.send({
    type: IpcMessageType.AllowAlwaysCommand,
    allowAlways: { domain, processName },
  }) ?? false;
});

ipcMain.handle('remove-rule', async (_event, { domain, processName }) => {
  return pipeClient?.send({
    type: IpcMessageType.RemoveRuleCommand,
    removeRule: { domain, processName },
  }) ?? false;
});

ipcMain.handle('set-rule-enabled', async (_event, { domain, processName, enabled }) => {
  return pipeClient?.send({
    type: IpcMessageType.SetRuleEnabledCommand,
    setRuleEnabled: { domain, processName, enabled },
  }) ?? false;
});

ipcMain.handle('is-connected', () => pipeClient?.connected ?? false);

ipcMain.handle('get-events', (_e, query) => store.queryEvents(query));
ipcMain.handle('get-event', (_e, id) => store.getEvent(id));
ipcMain.handle('clear-history', () => { store.clearEvents(); return true; });
ipcMain.handle('get-settings', () => store.getSettings());
ipcMain.handle('update-settings', (_e, partial) => {
  const updated = store.updateSettings(partial);
  if (partial.language) {
    rebuildTrayMenu();
    setTrayState(currentTrayState);
  }
  return updated;
});

ipcMain.handle('open-logs-folder', () => {
  const logsDir = path.join(process.env.ProgramData || 'C:\\ProgramData', 'AntiGrabber', 'logs');
  return shell.openPath(logsDir);
});

ipcMain.handle('export-history', async () => {
  const events = store.getAllEvents();
  if (!events.length) return { ok: false, reason: 'empty' };

  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: translate(store.getSettings().language, 'export.dialogTitle'),
    defaultPath: `antigrabber-historico-${new Date().toISOString().slice(0, 10)}.json`,
    filters: [
      { name: 'JSON', extensions: ['json'] },
      { name: 'CSV', extensions: ['csv'] },
    ],
  });
  if (canceled || !filePath) return { ok: false, reason: 'canceled' };

  const content = filePath.toLowerCase().endsWith('.csv') ? eventsToCsv(events) : JSON.stringify(events, null, 2);
  fs.writeFileSync(filePath, content, 'utf8');
  return { ok: true, filePath };
});

function eventsToCsv(events) {
  const cols = ['timestamp', 'processName', 'domain', 'correlatedFileAccess', 'correlatedFilePath', 'pid', 'localPort', 'plainLanguageMessage'];
  const escape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [cols.join(',')];
  for (const ev of events) rows.push(cols.map((c) => escape(ev[c])).join(','));
  return rows.join('\r\n');
}

ipcMain.on('window-minimize', () => mainWindow?.hide());
ipcMain.on('window-close', () => mainWindow?.hide());
