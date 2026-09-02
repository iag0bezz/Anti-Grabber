'use strict';

const path = require('node:path');
const { app, Tray, Menu, BrowserWindow, ipcMain, Notification, nativeImage, shell } = require('electron');
const { PipeClient, IpcMessageType } = require('./ipc/pipeClient');
const { Store } = require('./store');

const ASSETS_DIR = path.join(__dirname, '..', 'assets');
const TRAY_ICONS = {
  idle: nativeImage.createFromPath(path.join(ASSETS_DIR, 'tray-idle.ico')),
  active: nativeImage.createFromPath(path.join(ASSETS_DIR, 'tray-active.ico')),
  block: nativeImage.createFromPath(path.join(ASSETS_DIR, 'tray-block.ico')),
};

let tray = null;
let mainWindow = null;
let pipeClient = null;
let store = null;
let revertTimer = null;

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

  const menu = Menu.buildFromTemplate([
    { label: 'Abrir AntiGrabber', click: () => showWindow() },
    { type: 'separator' },
    { label: 'Sair', click: () => app.exit(0) },
  ]);
  tray.setContextMenu(menu);
  tray.on('double-click', () => showWindow());
}

function setTrayState(state) {
  const icon = TRAY_ICONS[state] ?? TRAY_ICONS.idle;
  tray.setImage(icon);
  tray.setToolTip(
    state === 'active' ? 'AntiGrabber — protegendo' :
    state === 'block' ? 'AntiGrabber — bloqueio recente' :
    'AntiGrabber — ocioso'
  );
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 440,
    height: 640,
    minWidth: 380,
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
    const fs = require('node:fs');
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

      case IpcMessageType.BlockEvent: {
        const stored = store.addEvent(envelope.blockEvent);
        send('block-event', stored);
        setTrayState('block');
        if (store.getSettings().notificationsEnabled) showBlockNotification(stored);
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
  new Notification({
    title: 'AntiGrabber bloqueou uma tentativa',
    body: ev.plainLanguageMessage || `Bloqueamos uma conexão de ${ev.processName} para ${ev.domain}.`,
  }).show();
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

ipcMain.handle('is-connected', () => pipeClient?.connected ?? false);

ipcMain.handle('get-events', (_e, query) => store.queryEvents(query));
ipcMain.handle('clear-history', () => { store.clearEvents(); return true; });
ipcMain.handle('get-settings', () => store.getSettings());
ipcMain.handle('update-settings', (_e, partial) => store.updateSettings(partial));

ipcMain.handle('open-logs-folder', () => {
  const logsDir = path.join(process.env.ProgramData || 'C:\\ProgramData', 'AntiGrabber', 'logs');
  return shell.openPath(logsDir);
});

ipcMain.on('window-minimize', () => mainWindow?.hide());
ipcMain.on('window-close', () => mainWindow?.hide());
