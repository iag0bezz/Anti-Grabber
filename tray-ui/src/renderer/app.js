'use strict';

function app() {
  return {
    connected: false,
    statusState: 'idle',
    blocksLast24h: 0,
    monitoredApps: [],

    tab: 'feed',

    events: [],
    page: 1,
    pageSize: 20,
    total: 0,
    totalPages: 1,
    loading: false,

    rules: [],
    newRuleDomain: '',
    newRuleProcess: '',

    search: '',
    correlatedOnly: false,
    sinceDays: '',

    notificationsEnabled: true,
    persistHistory: true,
    muteWhenFullscreen: true,
    notificationsSnoozedUntil: null,
    snoozeTick: 0,

    updateChannel: 'stable',
    configFeedback: '',

    language: 'pt',
    languageOptions: [
      { code: 'pt', label: 'Português' },
      { code: 'en', label: 'English' },
      { code: 'es', label: 'Español' },
    ],

    detailEvent: null,
    exportFeedback: '',

    appVersion: '',
    updateAvailable: null,
    updatePanelOpen: false,
    updateProgress: null,
    updateSteps: ['downloading', 'verifying', 'installing', 'relaunching'],

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
        if (this.page === 1 && this.tab === 'feed') this.loadFeed();
      });

      window.antigrabber.onOpenEventDetail((id) => {
        this.tab = 'feed';
        this.openDetailById(id);
      });

      window.antigrabber.onRulesSnapshot((rules) => {
        this.rules = rules;
      });

      window.antigrabber.onUpdateAvailable((info) => {
        this.updateAvailable = info;
      });

      window.antigrabber.onUpdateProgress((progress) => {
        this.updateProgress = progress;
      });

      window.antigrabber.getAppVersion().then((v) => { this.appVersion = v; });

      window.antigrabber.getSettings().then((s) => {
        this.notificationsEnabled = s.notificationsEnabled;
        this.persistHistory = s.persistHistory;
        this.muteWhenFullscreen = s.muteWhenFullscreen ?? true;
        this.notificationsSnoozedUntil = s.notificationsSnoozedUntil ?? null;
        this.language = s.language ?? 'pt';
        this.updateChannel = s.updateChannel ?? 'stable';
      });

      setInterval(() => { this.snoozeTick++; }, 30000);

      this.loadFeed();
    },

    t(key, vars) {
      return window.AG_I18N.translate(this.language, key, vars);
    },

    async setLanguage(lang) {
      this.language = lang;
      await window.antigrabber.updateSettings({ language: lang });
    },

    blockMessage(ev) {
      if (!ev) return '';
      return this.t(ev.correlatedFileAccess ? 'blockMsg.correlated' : 'blockMsg.suspicious', {
        process: ev.processName,
        domain: ev.domain,
      });
    },

    statusLabel() {
      if (!this.connected) return this.t('status.disconnected');
      if (this.statusState === 'recentBlock') return this.t('status.recentBlock');
      if (this.statusState === 'active') return this.t('status.active');
      return this.t('status.idle');
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

    isAllowed(domain, processName) {
      return this.rules.some((r) =>
        r.enabled &&
        r.domain.toLowerCase() === (domain || '').toLowerCase() &&
        r.processName.toLowerCase() === (processName || '').toLowerCase());
    },

    async allow(ev) {
      await window.antigrabber.allowAlways(ev.domain, ev.processName);
    },

    async addRule() {
      const domain = this.newRuleDomain.trim();
      const processName = this.newRuleProcess.trim();
      if (!domain || !processName) return;
      await window.antigrabber.allowAlways(domain, processName);
      this.newRuleDomain = '';
      this.newRuleProcess = '';
    },

    async toggleRule(rule) {
      await window.antigrabber.setRuleEnabled(rule.domain, rule.processName, !rule.enabled);
    },

    async revokeRule(rule) {
      await window.antigrabber.removeRule(rule.domain, rule.processName);
    },

    openDetail(ev) {
      this.detailEvent = ev;
    },

    async openDetailById(id) {
      const ev = this.events.find((e) => e.id === id) || await window.antigrabber.getEvent(id);
      if (ev) this.detailEvent = ev;
    },

    async saveSettings() {
      await window.antigrabber.updateSettings({
        notificationsEnabled: this.notificationsEnabled,
        persistHistory: this.persistHistory,
        muteWhenFullscreen: this.muteWhenFullscreen,
      });
    },

    async setUpdateChannel(channel) {
      this.updateChannel = channel;
      await window.antigrabber.updateSettings({ updateChannel: channel });
    },

    async exportConfig() {
      const result = await window.antigrabber.exportConfig();
      this.configFeedback = result.ok ? this.t('settings.exportConfigSuccess') : '';
      if (result.ok) setTimeout(() => { this.configFeedback = ''; }, 4000);
    },

    async importConfig() {
      const result = await window.antigrabber.importConfig();
      if (result.ok) {
        this.configFeedback = this.t('settings.importConfigSuccess');
        const s = result.settings;
        this.notificationsEnabled = s.notificationsEnabled;
        this.persistHistory = s.persistHistory;
        this.muteWhenFullscreen = s.muteWhenFullscreen ?? true;
        this.language = s.language ?? 'pt';
        this.updateChannel = s.updateChannel ?? 'stable';
      } else if (result.reason === 'invalid') {
        this.configFeedback = this.t('settings.importConfigError');
      } else {
        return;
      }
      setTimeout(() => { this.configFeedback = ''; }, 4000);
    },

    snoozeActive() {
      this.snoozeTick;
      if (!this.notificationsSnoozedUntil) return false;
      if (this.notificationsSnoozedUntil === 'indefinite') return true;
      return Date.now() < this.notificationsSnoozedUntil;
    },

    snoozeLabel() {
      if (this.notificationsSnoozedUntil === 'indefinite') return this.t('snooze.indefiniteLabel');
      const mins = Math.max(0, Math.round((this.notificationsSnoozedUntil - Date.now()) / 60000));
      if (mins < 60) return this.t('snooze.minRemaining', { n: mins });
      return this.t('snooze.hourRemaining', { n: Math.round(mins / 60) });
    },

    async snoozeFor(minutes) {
      this.notificationsSnoozedUntil = Date.now() + minutes * 60000;
      await window.antigrabber.updateSettings({ notificationsSnoozedUntil: this.notificationsSnoozedUntil });
    },

    async snoozeIndefinite() {
      this.notificationsSnoozedUntil = 'indefinite';
      await window.antigrabber.updateSettings({ notificationsSnoozedUntil: 'indefinite' });
    },

    async clearSnooze() {
      this.notificationsSnoozedUntil = null;
      await window.antigrabber.updateSettings({ notificationsSnoozedUntil: null });
    },

    async clearHistory() {
      await window.antigrabber.clearHistory();
      this.page = 1;
      await this.loadFeed();
    },

    openLogsFolder() {
      window.antigrabber.openLogsFolder();
    },

    async exportHistory() {
      const result = await window.antigrabber.exportHistory();
      if (result.ok) {
        this.exportFeedback = this.t('settings.exportSuccess');
      } else if (result.reason === 'empty') {
        this.exportFeedback = this.t('settings.exportEmpty');
      } else {
        this.exportFeedback = '';
        return;
      }
      setTimeout(() => { this.exportFeedback = ''; }, 4000);
    },

    async startUpdate() {
      this.updateProgress = { phase: 'downloading', percent: 0 };
      await window.antigrabber.startUpdate();
    },

    async skipUpdateVersion() {
      if (!this.updateAvailable) return;
      await window.antigrabber.skipUpdateVersion(this.updateAvailable.version);
      this.updateAvailable = null;
      this.updatePanelOpen = false;
    },

    remindUpdateLater() {
      this.updatePanelOpen = false;
    },

    async checkForUpdateNow() {
      await window.antigrabber.checkForUpdateNow();
    },

    updatePhaseLabel() {
      if (!this.updateProgress) return '';
      if (this.updateProgress.phase === 'downloading') {
        return this.t('update.phase.downloading', { percent: this.updateProgress.percent ?? 0 });
      }
      if (this.updateProgress.phase === 'error') return this.t('update.phase.error');
      return this.t('update.phase.' + this.updateProgress.phase);
    },

    updateStepState(step) {
      if (!this.updateProgress) return 'pending';
      const idx = this.updateSteps.indexOf(step);
      const curIdx = this.updateSteps.indexOf(this.updateProgress.phase);
      if (curIdx === -1) return 'pending';
      if (idx < curIdx) return 'done';
      if (idx === curIdx) return 'active';
      return 'pending';
    },

    updatePhaseDescription() {
      if (!this.updateProgress || this.updateProgress.phase === 'error') return '';
      return this.t('update.desc.' + this.updateProgress.phase);
    },

    dismissUpdateError() {
      this.updateProgress = null;
      this.updatePanelOpen = false;
    },

    locale() {
      return window.AG_I18N.localeTag(this.language);
    },

    formatTime(iso) {
      return new Date(iso).toLocaleString(this.locale());
    },

    formatRowTime(iso) {
      const d = new Date(iso);
      const sameDay = d.toDateString() === new Date().toDateString();
      const time = d.toLocaleTimeString(this.locale(), { hour: '2-digit', minute: '2-digit' });
      return sameDay ? time : `${d.toLocaleDateString(this.locale(), { day: '2-digit', month: '2-digit' })} ${time}`;
    },

    formatFullTime(iso) {
      return new Date(iso).toLocaleString(this.locale(), {
        dateStyle: 'full',
        timeStyle: 'medium',
      });
    },

    minimize() { window.antigrabber.minimize(); },
    close() { window.antigrabber.close(); },
  };
}
