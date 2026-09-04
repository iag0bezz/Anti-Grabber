'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { app } = require('electron');

const MAX_EVENTS = 1000;

const DEFAULT_SETTINGS = {
  persistHistory: true,
  notificationsEnabled: true,
  notificationsSnoozedUntil: null, // null = off, 'indefinite' = until re-enabled, number = epoch ms
};

function userDataDir() {
  return app.getPath('userData');
}

function eventsPath() {
  return path.join(userDataDir(), 'events.json');
}

function settingsPath() {
  return path.join(userDataDir(), 'settings.json');
}

class Store {
  constructor() {
    this.settings = this._loadSettings();
    this.events = this.settings.persistHistory ? this._loadEvents() : [];
  }

  _loadSettings() {
    try {
      const raw = fs.readFileSync(settingsPath(), 'utf8');
      return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }

  _saveSettings() {
    try {
      fs.mkdirSync(userDataDir(), { recursive: true });
      fs.writeFileSync(settingsPath(), JSON.stringify(this.settings, null, 2));
    } catch {
    }
  }

  _loadEvents() {
    try {
      const raw = fs.readFileSync(eventsPath(), 'utf8');
      const arr = JSON.parse(raw);
      return Array.isArray(arr) ? arr : [];
    } catch {
      return [];
    }
  }

  _saveEvents() {
    if (!this.settings.persistHistory) return;
    try {
      fs.mkdirSync(userDataDir(), { recursive: true });
      fs.writeFileSync(eventsPath(), JSON.stringify(this.events.slice(0, MAX_EVENTS)));
    } catch {
    }
  }

  getSettings() {
    return { ...this.settings };
  }

  updateSettings(partial) {
    const wasPersisting = this.settings.persistHistory;
    this.settings = { ...this.settings, ...partial };
    this._saveSettings();

    if (!this.settings.persistHistory && wasPersisting) {
      try { fs.unlinkSync(eventsPath()); } catch { }
    }
    return this.getSettings();
  }

  addEvent(ev) {
    const withId = { ...ev, id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}` };
    this.events.unshift(withId);
    if (this.events.length > MAX_EVENTS) this.events.length = MAX_EVENTS;
    this._saveEvents();
    return withId;
  }

  clearEvents() {
    this.events = [];
    try { fs.unlinkSync(eventsPath()); } catch { }
  }

  getEvent(id) {
    return this.events.find((e) => e.id === id) ?? null;
  }

  getAllEvents() {
    return [...this.events];
  }

  notificationsSnoozed() {
    const until = this.settings.notificationsSnoozedUntil;
    if (!until) return false;
    if (until === 'indefinite') return true;
    return Date.now() < until;
  }

  queryEvents({ page = 1, pageSize = 20, search = '', correlatedOnly = false, sinceDays = null } = {}) {
    let filtered = this.events;

    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter((e) =>
        (e.domain || '').toLowerCase().includes(q) ||
        (e.processName || '').toLowerCase().includes(q));
    }
    if (correlatedOnly) {
      filtered = filtered.filter((e) => e.correlatedFileAccess);
    }
    if (sinceDays) {
      const cutoff = Date.now() - sinceDays * 24 * 60 * 60 * 1000;
      filtered = filtered.filter((e) => new Date(e.timestamp).getTime() >= cutoff);
    }

    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const clampedPage = Math.min(Math.max(1, page), totalPages);
    const start = (clampedPage - 1) * pageSize;

    return {
      items: filtered.slice(start, start + pageSize),
      total,
      page: clampedPage,
      pageSize,
      totalPages,
    };
  }
}

module.exports = { Store };
