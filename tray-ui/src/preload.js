'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('antigrabber', {
  onConnectionStatus: (cb) => ipcRenderer.on('connection-status', (_e, data) => cb(data)),
  onStatus: (cb) => ipcRenderer.on('status', (_e, data) => cb(data)),
  onBlockEvent: (cb) => ipcRenderer.on('block-event', (_e, data) => cb(data)),
  onOpenEventDetail: (cb) => ipcRenderer.on('open-event-detail', (_e, id) => cb(id)),
  onRulesSnapshot: (cb) => ipcRenderer.on('rules-snapshot', (_e, rules) => cb(rules)),
  allowAlways: (domain, processName) => ipcRenderer.invoke('allow-always', { domain, processName }),
  removeRule: (domain, processName) => ipcRenderer.invoke('remove-rule', { domain, processName }),
  setRuleEnabled: (domain, processName, enabled) => ipcRenderer.invoke('set-rule-enabled', { domain, processName, enabled }),
  isConnected: () => ipcRenderer.invoke('is-connected'),

  getEvents: (query) => ipcRenderer.invoke('get-events', query),
  getEvent: (id) => ipcRenderer.invoke('get-event', id),
  clearHistory: () => ipcRenderer.invoke('clear-history'),
  exportHistory: () => ipcRenderer.invoke('export-history'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (partial) => ipcRenderer.invoke('update-settings', partial),
  openLogsFolder: () => ipcRenderer.invoke('open-logs-folder'),

  minimize: () => ipcRenderer.send('window-minimize'),
  close: () => ipcRenderer.send('window-close'),
});
