'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('antigrabber', {
  onConnectionStatus: (cb) => ipcRenderer.on('connection-status', (_e, data) => cb(data)),
  onStatus: (cb) => ipcRenderer.on('status', (_e, data) => cb(data)),
  onBlockEvent: (cb) => ipcRenderer.on('block-event', (_e, data) => cb(data)),
  allowAlways: (domain, processName) => ipcRenderer.invoke('allow-always', { domain, processName }),
  isConnected: () => ipcRenderer.invoke('is-connected'),

  getEvents: (query) => ipcRenderer.invoke('get-events', query),
  clearHistory: () => ipcRenderer.invoke('clear-history'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (partial) => ipcRenderer.invoke('update-settings', partial),
  openLogsFolder: () => ipcRenderer.invoke('open-logs-folder'),

  minimize: () => ipcRenderer.send('window-minimize'),
  close: () => ipcRenderer.send('window-close'),
});
