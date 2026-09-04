'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawn, execFile } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const { app, Tray, Menu, BrowserWindow, ipcMain, Notification, nativeImage, shell, dialog, net } = require('electron');
const { PipeClient, IpcMessageType } = require('./ipc/pipeClient');
const { Store } = require('./store');
const { translate } = require('./renderer/i18n');

const ASSETS_DIR = path.join(__dirname, '..', 'assets');
const SCRIPTS_DIR = path.join(__dirname, '..', 'scripts');
const GITHUB_REPO = 'iag0bezz/Anti-Grabber';
const UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
const HTTPS_TIMEOUT_MS = 15000; // sem isso um travamento de rede prende checkForUpdate/performUpdate pra sempre
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
let pendingUpdate = null; // { version, notes, zipUrl, shaUrl }
let updateInProgress = false;

app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu-sandbox');

if (!app.requestSingleInstanceLock()) {
  // app.quit() é assíncrono/gracioso — sem esse return o resto do módulo continuava
  // rodando numa instância que já tá saindo (whenReady() ainda dispara, registra tudo,
  // e corre contra o teardown do quit(); qualquer coisa async em andamento nesse meio-
  // tempo, tipo uma request de rede, pode morrer travada sem erro nem resposta).
  app.quit();
  return;
}

app.on('second-instance', () => showWindow());

app.whenReady().then(() => {
  app.setAppUserModelId('com.antigrabber.tray');
  store = new Store();
  createTray();
  createWindow();
  connectToService();
  scheduleUpdateChecks();
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

// --- Auto-update ---
// Checa GitHub Releases periodicamente; só baixa/aplica quando o usuário clica confirmar.
// Nunca re-baixa o runtime Electron nem o WinDivert — só Service.exe + código do Tray
// (ver scripts/package-update.ps1). Elevação via helper PowerShell (scripts/update-helper.ps1),
// mesmo padrão manual usado esta sessão pra trocar arquivos em Program Files.

// Usa electron.net em vez de node:https: o https/http nativo do Node trava sem erro
// nem timeout dentro do processo principal do Electron em algumas configurações de rede
// do Windows (proxy auto-detect do WinINET) — net.request usa a stack de rede do Chromium
// (a mesma que a janela principal já usa) e segue redirect automaticamente, então nem
// precisa da lógica manual de seguir Location que o node:https exigiria.

function withTimeout(req, reject) {
  const timer = setTimeout(() => {
    req.abort();
    reject(new Error('timeout'));
  }, HTTPS_TIMEOUT_MS);
  return () => clearTimeout(timer);
}

function httpsJson(url) {
  return new Promise((resolve, reject) => {
    const req = net.request({ url, method: 'GET' });
    req.setHeader('User-Agent', 'AntiGrabber-Tray');
    const clearTimer = withTimeout(req, reject);
    req.on('response', (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        clearTimer();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        clearTimer();
        try { resolve(JSON.parse(data)); } catch (err) { reject(err); }
      });
    });
    req.on('error', (err) => { clearTimer(); reject(err); });
    req.end();
  });
}

function httpsText(url) {
  return new Promise((resolve, reject) => {
    const req = net.request({ url, method: 'GET' });
    req.setHeader('User-Agent', 'AntiGrabber-Tray');
    const clearTimer = withTimeout(req, reject);
    req.on('response', (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        clearTimer();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => { clearTimer(); resolve(data); });
    });
    req.on('error', (err) => { clearTimer(); reject(err); });
    req.end();
  });
}

function httpsDownload(url, destPath, onProgress) {
  return new Promise((resolve, reject) => {
    const req = net.request({ url, method: 'GET' });
    req.setHeader('User-Agent', 'AntiGrabber-Tray');
    const clearTimer = withTimeout(req, reject);
    req.on('response', (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        clearTimer();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      // headers do electron.net vêm como array de strings por chave, não string direto
      const total = Number((res.headers['content-length'] || [])[0] || 0);
      let received = 0;
      const fileStream = fs.createWriteStream(destPath);
      res.on('data', (chunk) => {
        received += chunk.length;
        if (onProgress && total) onProgress(Math.round((received / total) * 100));
      });
      res.pipe(fileStream);
      fileStream.on('finish', () => { clearTimer(); fileStream.close(() => resolve()); });
      fileStream.on('error', (err) => { clearTimer(); reject(err); });
    });
    req.on('error', (err) => { clearTimer(); reject(err); });
    req.end();
  });
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function extractZip(zipPath, destDir) {
  return new Promise((resolve, reject) => {
    execFile('powershell', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
      `Expand-Archive -Path "${zipPath}" -DestinationPath "${destDir}" -Force`,
    ], { windowsHide: true }, (err) => (err ? reject(err) : resolve()));
  });
}

function runElevatedHelper(scriptPath, stagingDir, installDir) {
  return new Promise((resolve) => {
    const resultFile = path.join(app.getPath('temp'), `antigrabber-update-result-${Date.now()}.txt`);
    const esc = (s) => s.replace(/'/g, "''");
    const psCommand =
      `try { $p = Start-Process -FilePath 'powershell' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${esc(scriptPath)}','-StagingDir','${esc(stagingDir)}','-InstallDir','${esc(installDir)}' -Verb RunAs -Wait -PassThru; $p.ExitCode | Out-File -FilePath '${esc(resultFile)}' -Encoding ascii } catch { '1' | Out-File -FilePath '${esc(resultFile)}' -Encoding ascii }`;

    const child = spawn('powershell', ['-NoProfile', '-Command', psCommand], { windowsHide: true });
    child.on('exit', () => {
      try {
        const raw = fs.readFileSync(resultFile, 'utf8').trim();
        fs.unlinkSync(resultFile);
        resolve(raw === '0');
      } catch {
        resolve(false);
      }
    });
    child.on('error', () => resolve(false));
  });
}

async function checkForUpdate() {
  if (!app.isPackaged) return;
  try {
    const release = await httpsJson(`https://api.github.com/repos/${GITHUB_REPO}/releases/latest`);
    const remoteVersion = String(release.tag_name || '').replace(/^v/, '');
    if (!remoteVersion) return;

    store.updateSettings({ lastUpdateCheck: Date.now() });

    if (compareVersions(remoteVersion, app.getVersion()) <= 0) return;
    if (store.getSettings().skippedVersion === remoteVersion) return;

    const assets = release.assets || [];
    const zipAsset = assets.find((a) => a.name === `AntiGrabberUpdate-${remoteVersion}.zip`);
    const shaAsset = assets.find((a) => a.name === `AntiGrabberUpdate-${remoteVersion}.zip.sha256`);
    if (!zipAsset || !shaAsset) return;

    pendingUpdate = {
      version: remoteVersion,
      notes: release.body || '',
      zipUrl: zipAsset.browser_download_url,
      shaUrl: shaAsset.browser_download_url,
    };
    send('update-available', { version: remoteVersion, notes: pendingUpdate.notes });
  } catch {
    // offline, GitHub fora do ar, rate limit — nunca vira erro visível pro usuário.
  }
}

function scheduleUpdateChecks() {
  checkForUpdate();
  setInterval(checkForUpdate, UPDATE_CHECK_INTERVAL_MS);
}

async function performUpdate() {
  if (!pendingUpdate || updateInProgress) return;
  updateInProgress = true;
  const version = pendingUpdate.version;

  try {
    const workDir = path.join(app.getPath('userData'), 'updates', version);
    fs.mkdirSync(workDir, { recursive: true });
    const zipPath = path.join(workDir, 'update.zip');
    const extractDir = path.join(workDir, 'extracted');

    send('update-progress', { phase: 'downloading', percent: 0 });
    await httpsDownload(pendingUpdate.zipUrl, zipPath, (percent) => {
      send('update-progress', { phase: 'downloading', percent });
    });

    send('update-progress', { phase: 'verifying' });
    const shaText = await httpsText(pendingUpdate.shaUrl);
    const expectedHash = (shaText.trim().split(/\s+/)[0] || '').toLowerCase();
    const actualHash = (await sha256File(zipPath)).toLowerCase();
    if (!expectedHash || actualHash !== expectedHash) throw new Error('hash-mismatch-zip');

    send('update-progress', { phase: 'extracting' });
    if (fs.existsSync(extractDir)) fs.rmSync(extractDir, { recursive: true, force: true });
    fs.mkdirSync(extractDir, { recursive: true });
    await extractZip(zipPath, extractDir);

    const manifest = JSON.parse(fs.readFileSync(path.join(extractDir, 'manifest.json'), 'utf8'));
    for (const f of manifest.files) {
      const hash = (await sha256File(path.join(extractDir, f.path))).toLowerCase();
      if (hash !== String(f.sha256).toLowerCase()) throw new Error(`hash-mismatch-file:${f.path}`);
    }

    send('update-progress', { phase: 'elevating' });
    const installRoot = path.dirname(path.dirname(process.resourcesPath));
    const helperScript = path.join(SCRIPTS_DIR, 'update-helper.ps1');
    const ok = await runElevatedHelper(helperScript, extractDir, installRoot);
    if (!ok) throw new Error('helper-failed');

    send('update-progress', { phase: 'relaunching' });
    fs.rmSync(workDir, { recursive: true, force: true });
    app.relaunch();
    app.exit(0);
  } catch (err) {
    send('update-progress', { phase: 'error', message: String(err?.message || err) });
    updateInProgress = false;
  }
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

ipcMain.handle('get-app-version', () => app.getVersion());
ipcMain.handle('check-for-update-now', () => { checkForUpdate(); return true; });
ipcMain.handle('start-update', () => { performUpdate(); return true; });
ipcMain.handle('skip-update-version', (_e, version) => store.updateSettings({ skippedVersion: version }));

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
