'use strict';

// Substitui o preload.js/contextBridge do Electron. WebView2 expõe
// window.chrome.webview.postMessage (página -> host) e um listener 'message'
// (host -> página); não é RPC nativo, então correlaciona por id: pedidos viram
// { id, channel, args }, respostas { id, result } ou { id, error }. Eventos
// não solicitados (status, block-event, etc.) chegam como { channel, payload },
// sem id. Implementa a MESMA superfície de window.antigrabber que preload.js
// expunha — index.html/app.js/i18n.js não mudam nada.

(function () {
  if (!window.chrome || !window.chrome.webview) return; // build Electron ainda ativo: preload.js já cobre isso

  let nextId = 1;
  const pending = new Map();
  const listeners = new Map(); // channel -> Set<callback>

  function on(channel, cb) {
    if (!listeners.has(channel)) listeners.set(channel, new Set());
    listeners.get(channel).add(cb);
  }

  function call(channel, args) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      window.chrome.webview.postMessage({ id, channel, args });
    });
  }

  window.chrome.webview.addEventListener('message', (e) => {
    const data = e.data;
    if (!data) return;
    if (data.id !== undefined) {
      const p = pending.get(data.id);
      if (!p) return;
      pending.delete(data.id);
      if (data.error) p.reject(new Error(data.error));
      else p.resolve(data.result);
      return;
    }
    if (data.channel) {
      const cbs = listeners.get(data.channel);
      if (cbs) for (const cb of cbs) cb(data.payload);
    }
  });

  window.antigrabber = {
    onConnectionStatus: (cb) => on('connection-status', cb),
    onStatus: (cb) => on('status', cb),
    onBlockEvent: (cb) => on('block-event', cb),
    onOpenEventDetail: (cb) => on('open-event-detail', cb),
    onRulesSnapshot: (cb) => on('rules-snapshot', cb),
    onUpdateAvailable: (cb) => on('update-available', cb),
    onUpdateProgress: (cb) => on('update-progress', cb),

    allowAlways: (domain, processName) => call('allow-always', { domain, processName }),
    removeRule: (domain, processName) => call('remove-rule', { domain, processName }),
    setRuleEnabled: (domain, processName, enabled) => call('set-rule-enabled', { domain, processName, enabled }),
    isConnected: () => call('is-connected'),

    getEvents: (query) => call('get-events', query),
    getEvent: (id) => call('get-event', id),
    clearHistory: () => call('clear-history'),
    exportHistory: () => call('export-history'),
    getSettings: () => call('get-settings'),
    updateSettings: (partial) => call('update-settings', partial),
    openLogsFolder: () => call('open-logs-folder'),

    getAppVersion: () => call('get-app-version'),
    checkForUpdateNow: () => call('check-for-update-now'),
    startUpdate: () => call('start-update'),
    skipUpdateVersion: (version) => call('skip-update-version', version),

    minimize: () => call('window-minimize'),
    close: () => call('window-close'),
  };

  // Arraste da janela sem moldura: -webkit-app-region:drag não existe no
  // WebView2 puro. No mousedown na titlebar, avisa o host, que entrega o
  // arraste pro próprio Windows (ReleaseCapture + WM_NCLBUTTONDOWN/HTCAPTION).
  document.addEventListener('DOMContentLoaded', () => {
    const dragEl = document.querySelector('.titlebar-drag');
    if (!dragEl) return;
    dragEl.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      if (e.target.closest('button, input, select, a')) return;
      window.chrome.webview.postMessage({ channel: 'begin-drag' });
    });
  });
})();
