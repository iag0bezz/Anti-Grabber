'use strict';

function app() {
  return {
    connected: false,
    statusState: 'idle',
    blocksLast24h: 0,
    monitoredApps: [],

    events: [],
    page: 1,
    pageSize: 20,
    total: 0,
    totalPages: 1,
    loading: false,
    allowedIds: new Set(),

    search: '',
    correlatedOnly: false,
    sinceDays: '',
    filterOpen: false,

    notificationsEnabled: true,
    persistHistory: true,
    settingsOpen: false,

    init() {
      window.antigrabber.onConnectionStatus(({ connected }) => {
        this.connected = connected;
        if (!connected) this.statusState = 'idle';
      });

      window.antigrabber.onStatus((status) => {
        this.connected = true;
        this.statusState = status.state === 'recentBlock' ? 'recentBlock' : 'active';
        this.blocksLast24h = status.blocksLast24h ?? 0;
        this.monitoredApps = status.monitoredApps ?? [];
      });

      window.antigrabber.onBlockEvent(() => {
        if (this.page === 1) this.loadFeed();
      });

      window.antigrabber.getSettings().then((s) => {
        this.notificationsEnabled = s.notificationsEnabled;
        this.persistHistory = s.persistHistory;
      });

      this.loadFeed();
    },

    statusLabel() {
      if (!this.connected) return 'Não conectado';
      if (this.statusState === 'recentBlock') return 'Bloqueio recente';
      if (this.statusState === 'active') return 'Protegendo';
      return 'Ocioso';
    },

    hasActiveFilters() {
      return !!(this.search || this.correlatedOnly || this.sinceDays);
    },

    async loadFeed() {
      this.loading = true;
      const result = await window.antigrabber.getEvents({
        page: this.page,
        pageSize: this.pageSize,
        search: this.search.trim(),
        correlatedOnly: this.correlatedOnly,
        sinceDays: this.sinceDays ? Number(this.sinceDays) : null,
      });
      this.events = result.items;
      this.total = result.total;
      this.page = result.page;
      this.totalPages = result.totalPages;
      this.loading = false;
    },

    async allow(ev) {
      this.allowedIds.add(ev.id);
      this.allowedIds = new Set(this.allowedIds);
      await window.antigrabber.allowAlways(ev.domain, ev.processName);
    },

    async saveSettings() {
      await window.antigrabber.updateSettings({
        notificationsEnabled: this.notificationsEnabled,
        persistHistory: this.persistHistory,
      });
    },

    async clearHistory() {
      await window.antigrabber.clearHistory();
      this.page = 1;
      await this.loadFeed();
    },

    openLogsFolder() {
      window.antigrabber.openLogsFolder();
    },

    formatTime(iso) {
      return new Date(iso).toLocaleString('pt-BR');
    },

    minimize() { window.antigrabber.minimize(); },
    close() { window.antigrabber.close(); },
  };
}
