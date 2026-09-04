'use strict';

// Fonte única de tradução: main.js (processo principal) usa via require() normal; o
// renderer carrega este arquivo direto como <script> (preload sandboxado não consegue
// require() arquivo local — só builtins/electron). Por isso o wrapper UMD no fim do
// arquivo. Chave plana com namespace por ponto; valor string (com {placeholders}) ou
// função(vars) pra casos sensíveis a plural/gênero.

const DEFAULT_LANGUAGE = 'pt';

const LOCALE_TAGS = {
  pt: 'pt-BR',
  en: 'en-US',
  es: 'es-ES',
};

const dict = {
  pt: {
    'title.minimize': 'Minimizar',
    'title.close': 'Fechar',

    'status.disconnected': 'Não conectado',
    'status.recentBlock': 'Bloqueio recente',
    'status.active': 'Protegendo',
    'status.idle': 'Ocioso',

    'nav.activity': 'Atividade',
    'nav.exceptions': 'Exceções',
    'nav.settings': 'Config',
    'nav.settingsFull': 'Configurações',
    'rail.blocks24hTitle': 'Bloqueios nas últimas 24h',

    'feed.searchPlaceholder': 'Buscar por domínio ou programa...',
    'feed.fileAccessOnly': 'Só com acesso a arquivo',
    'feed.periodAll': 'Todo o período',
    'feed.periodToday': 'Hoje',
    'feed.period7d': '7 dias',
    'feed.period30d': '30 dias',
    'feed.count': (v) => `${v.n} bloqueio${v.n === 1 ? '' : 's'}`,
    'feed.emptyFiltered': 'Nenhum bloqueio bate com esse filtro.',
    'feed.emptyNone': 'Nenhum bloqueio ainda. Quando bloquearmos alguma tentativa de roubo, ela aparece aqui.',
    'feed.fileChip': 'Arquivo',
    'feed.allow': 'Permitir',
    'feed.allowed': 'Permitido',

    'exceptions.domainPlaceholder': 'Domínio (ex: discord.com)',
    'exceptions.processPlaceholder': 'Programa (ex: Discord.exe)',
    'exceptions.create': 'Criar exceção',
    'exceptions.count': (v) => `${v.n} exceç${v.n === 1 ? 'ão' : 'ões'}`,
    'exceptions.emptyState': 'Nenhuma exceção criada ainda. Quando você clicar em "Permitir" num bloqueio, ou criar uma manualmente aqui em cima, ela aparece nesta lista.',
    'exceptions.since': 'desde {date}',
    'exceptions.disable': 'Desativar exceção',
    'exceptions.enable': 'Reativar exceção',
    'exceptions.revoke': 'Revogar',

    'settings.notifications': 'Notificações',
    'settings.notifyOnBlock': 'Mostrar notificação ao bloquear',
    'settings.snoozeTitle': 'Silenciar notificações',
    'settings.snooze15': '15 min',
    'settings.snooze1h': '1 hora',
    'settings.snooze4h': '4 horas',
    'settings.snooze8h': '8 horas',
    'settings.snoozeIndefinite': 'Até eu reativar',
    'settings.snoozedPrefix': 'Silenciado: {label}',
    'settings.reactivateNow': 'Reativar agora',
    'snooze.indefiniteLabel': 'até você reativar',
    'snooze.minRemaining': (v) => `${v.n} min restantes`,
    'snooze.hourRemaining': (v) => `${v.n}h restantes`,
    'settings.language': 'Idioma',
    'settings.monitoredApps': 'Apps monitorados',
    'settings.noneDetected': 'Nenhum detectado ainda.',
    'settings.logs': 'Logs',
    'settings.openLogsFolder': 'Abrir pasta de logs do serviço',
    'settings.privacy': 'Privacidade e dados',
    'settings.privacyNote': 'Tudo nesta tela fica só neste computador — nada é enviado pra nenhum servidor. O serviço também nunca lê ou envia o conteúdo real dos seus arquivos, só nomes e metadados.',
    'settings.persistHistory': 'Guardar histórico neste computador',
    'settings.persistHistoryNote': 'Desligado: histórico some ao fechar o app.',
    'settings.exportHistory': 'Exportar histórico (.json/.csv)',
    'settings.exportSuccess': 'Exportado com sucesso.',
    'settings.exportEmpty': 'Nenhum bloqueio pra exportar ainda.',
    'settings.clearHistory': 'Apagar histórico agora',

    'detail.title': 'Bloqueio detalhado',
    'detail.process': 'Processo',
    'detail.pid': 'PID',
    'detail.localPort': 'Porta local',
    'detail.domain': 'Domínio de destino',
    'detail.protocol': 'Protocolo',
    'detail.protocolValue': 'TCP/443 (TLS, bloqueado no handshake)',
    'detail.timestamp': 'Data e hora',
    'detail.correlated': 'Acesso a arquivo correlacionado',
    'detail.correlatedYes': 'Sim, nos 10s anteriores',
    'detail.correlatedNo': 'Não',
    'detail.filePath': 'Arquivo acessado',
    'detail.allow': 'Permitir este programa sempre',
    'detail.allowed': 'Permitido sempre',

    'blockMsg.correlated': 'Bloqueamos uma tentativa de roubo: {process} tentou enviar dados para {domain} logo após acessar seus arquivos.',
    'blockMsg.suspicious': 'Bloqueamos uma conexão suspeita: {process} tentou falar com {domain} sem autorização.',

    'notif.title': 'AntiGrabber bloqueou uma tentativa',
    'notif.program': 'Programa: {process}',
    'notif.domain': 'Domínio: {domain}',
    'notif.correlatedNote': 'Acesso a arquivo sensível detectado logo antes',

    'tray.active': 'AntiGrabber — protegendo',
    'tray.block': 'AntiGrabber — bloqueio recente',
    'tray.idle': 'AntiGrabber — ocioso',
    'tray.unseenSuffix': (v) => ` (${v.n} não visto${v.n === 1 ? '' : 's'})`,

    'menu.open': 'Abrir AntiGrabber',
    'menu.quit': 'Sair',

    'export.dialogTitle': 'Exportar histórico de bloqueios',

    'update.pillLabel': 'Atualização disponível',
    'update.title': 'Nova versão: {version}',
    'update.noNotes': 'Sem notas de versão.',
    'update.updateNow': 'Atualizar agora',
    'update.skipVersion': 'Ignorar esta versão',
    'update.remindLater': 'Lembrar depois',
    'update.phase.downloading': 'Baixando... {percent}%',
    'update.phase.verifying': 'Verificando integridade...',
    'update.phase.installing': 'Instalando (permissão de administrador)...',
    'update.phase.relaunching': 'Reiniciando o AntiGrabber...',
    'update.phase.error': 'Falha ao atualizar. A versão atual continua funcionando normalmente.',
    'settings.updates': 'Atualizações',
    'settings.checkNow': 'Verificar agora',
    'settings.currentVersion': 'Versão instalada: {version}',
  },

  en: {
    'title.minimize': 'Minimize',
    'title.close': 'Close',

    'status.disconnected': 'Not connected',
    'status.recentBlock': 'Recent block',
    'status.active': 'Protecting',
    'status.idle': 'Idle',

    'nav.activity': 'Activity',
    'nav.exceptions': 'Exceptions',
    'nav.settings': 'Settings',
    'nav.settingsFull': 'Settings',
    'rail.blocks24hTitle': 'Blocks in the last 24h',

    'feed.searchPlaceholder': 'Search by domain or program...',
    'feed.fileAccessOnly': 'Only with file access',
    'feed.periodAll': 'All time',
    'feed.periodToday': 'Today',
    'feed.period7d': '7 days',
    'feed.period30d': '30 days',
    'feed.count': (v) => `${v.n} block${v.n === 1 ? '' : 's'}`,
    'feed.emptyFiltered': 'No blocks match this filter.',
    'feed.emptyNone': 'No blocks yet. When we block a theft attempt, it shows up here.',
    'feed.fileChip': 'File',
    'feed.allow': 'Allow',
    'feed.allowed': 'Allowed',

    'exceptions.domainPlaceholder': 'Domain (e.g. discord.com)',
    'exceptions.processPlaceholder': 'Program (e.g. Discord.exe)',
    'exceptions.create': 'Create exception',
    'exceptions.count': (v) => `${v.n} exception${v.n === 1 ? '' : 's'}`,
    'exceptions.emptyState': 'No exceptions yet. When you click "Allow" on a block, or create one manually above, it shows up in this list.',
    'exceptions.since': 'since {date}',
    'exceptions.disable': 'Disable exception',
    'exceptions.enable': 'Re-enable exception',
    'exceptions.revoke': 'Revoke',

    'settings.notifications': 'Notifications',
    'settings.notifyOnBlock': 'Show a notification when blocking',
    'settings.snoozeTitle': 'Snooze notifications',
    'settings.snooze15': '15 min',
    'settings.snooze1h': '1 hour',
    'settings.snooze4h': '4 hours',
    'settings.snooze8h': '8 hours',
    'settings.snoozeIndefinite': 'Until I turn it back on',
    'settings.snoozedPrefix': 'Snoozed: {label}',
    'settings.reactivateNow': 'Reactivate now',
    'snooze.indefiniteLabel': 'until you turn it back on',
    'snooze.minRemaining': (v) => `${v.n} min left`,
    'snooze.hourRemaining': (v) => `${v.n}h left`,
    'settings.language': 'Language',
    'settings.monitoredApps': 'Monitored apps',
    'settings.noneDetected': 'None detected yet.',
    'settings.logs': 'Logs',
    'settings.openLogsFolder': "Open the service's logs folder",
    'settings.privacy': 'Privacy and data',
    'settings.privacyNote': "Everything on this screen stays on this computer only — nothing is sent to any server. The service also never reads or sends the real content of your files, only names and metadata.",
    'settings.persistHistory': 'Keep history on this computer',
    'settings.persistHistoryNote': 'Off: history disappears when the app closes.',
    'settings.exportHistory': 'Export history (.json/.csv)',
    'settings.exportSuccess': 'Exported successfully.',
    'settings.exportEmpty': 'No blocks to export yet.',
    'settings.clearHistory': 'Clear history now',

    'detail.title': 'Block details',
    'detail.process': 'Process',
    'detail.pid': 'PID',
    'detail.localPort': 'Local port',
    'detail.domain': 'Destination domain',
    'detail.protocol': 'Protocol',
    'detail.protocolValue': 'TCP/443 (TLS, blocked at handshake)',
    'detail.timestamp': 'Date and time',
    'detail.correlated': 'Correlated file access',
    'detail.correlatedYes': 'Yes, within the previous 10s',
    'detail.correlatedNo': 'No',
    'detail.filePath': 'File accessed',
    'detail.allow': 'Always allow this program',
    'detail.allowed': 'Always allowed',

    'blockMsg.correlated': 'We blocked a theft attempt: {process} tried to send data to {domain} right after accessing your files.',
    'blockMsg.suspicious': 'We blocked a suspicious connection: {process} tried to reach {domain} without authorization.',

    'notif.title': 'AntiGrabber blocked an attempt',
    'notif.program': 'Program: {process}',
    'notif.domain': 'Domain: {domain}',
    'notif.correlatedNote': 'Sensitive file access detected right before',

    'tray.active': 'AntiGrabber — protecting',
    'tray.block': 'AntiGrabber — recent block',
    'tray.idle': 'AntiGrabber — idle',
    'tray.unseenSuffix': (v) => ` (${v.n} unseen)`,

    'menu.open': 'Open AntiGrabber',
    'menu.quit': 'Quit',

    'export.dialogTitle': 'Export block history',

    'update.pillLabel': 'Update available',
    'update.title': 'New version: {version}',
    'update.noNotes': 'No release notes.',
    'update.updateNow': 'Update now',
    'update.skipVersion': 'Skip this version',
    'update.remindLater': 'Remind me later',
    'update.phase.downloading': 'Downloading... {percent}%',
    'update.phase.verifying': 'Verifying integrity...',
    'update.phase.installing': 'Installing (administrator permission)...',
    'update.phase.relaunching': 'Restarting AntiGrabber...',
    'update.phase.error': 'Update failed. The current version keeps working normally.',
    'settings.updates': 'Updates',
    'settings.checkNow': 'Check now',
    'settings.currentVersion': 'Installed version: {version}',
  },

  es: {
    'title.minimize': 'Minimizar',
    'title.close': 'Cerrar',

    'status.disconnected': 'No conectado',
    'status.recentBlock': 'Bloqueo reciente',
    'status.active': 'Protegiendo',
    'status.idle': 'Inactivo',

    'nav.activity': 'Actividad',
    'nav.exceptions': 'Excepciones',
    'nav.settings': 'Config',
    'nav.settingsFull': 'Configuración',
    'rail.blocks24hTitle': 'Bloqueos en las últimas 24h',

    'feed.searchPlaceholder': 'Buscar por dominio o programa...',
    'feed.fileAccessOnly': 'Solo con acceso a archivo',
    'feed.periodAll': 'Todo el período',
    'feed.periodToday': 'Hoy',
    'feed.period7d': '7 días',
    'feed.period30d': '30 días',
    'feed.count': (v) => `${v.n} bloqueo${v.n === 1 ? '' : 's'}`,
    'feed.emptyFiltered': 'Ningún bloqueo coincide con este filtro.',
    'feed.emptyNone': 'Ningún bloqueo todavía. Cuando bloqueemos un intento de robo, aparecerá aquí.',
    'feed.fileChip': 'Archivo',
    'feed.allow': 'Permitir',
    'feed.allowed': 'Permitido',

    'exceptions.domainPlaceholder': 'Dominio (ej: discord.com)',
    'exceptions.processPlaceholder': 'Programa (ej: Discord.exe)',
    'exceptions.create': 'Crear excepción',
    'exceptions.count': (v) => `${v.n} excepci${v.n === 1 ? 'ón' : 'ones'}`,
    'exceptions.emptyState': 'Ninguna excepción creada todavía. Cuando hagas clic en "Permitir" en un bloqueo, o crees una manualmente aquí arriba, aparecerá en esta lista.',
    'exceptions.since': 'desde {date}',
    'exceptions.disable': 'Desactivar excepción',
    'exceptions.enable': 'Reactivar excepción',
    'exceptions.revoke': 'Revocar',

    'settings.notifications': 'Notificaciones',
    'settings.notifyOnBlock': 'Mostrar notificación al bloquear',
    'settings.snoozeTitle': 'Silenciar notificaciones',
    'settings.snooze15': '15 min',
    'settings.snooze1h': '1 hora',
    'settings.snooze4h': '4 horas',
    'settings.snooze8h': '8 horas',
    'settings.snoozeIndefinite': 'Hasta que lo reactive',
    'settings.snoozedPrefix': 'Silenciado: {label}',
    'settings.reactivateNow': 'Reactivar ahora',
    'snooze.indefiniteLabel': 'hasta que lo reactives',
    'snooze.minRemaining': (v) => `${v.n} min restantes`,
    'snooze.hourRemaining': (v) => `${v.n}h restantes`,
    'settings.language': 'Idioma',
    'settings.monitoredApps': 'Apps monitoreadas',
    'settings.noneDetected': 'Ninguna detectada todavía.',
    'settings.logs': 'Registros',
    'settings.openLogsFolder': 'Abrir carpeta de registros del servicio',
    'settings.privacy': 'Privacidad y datos',
    'settings.privacyNote': 'Todo en esta pantalla queda solo en este equipo — nada se envía a ningún servidor. El servicio tampoco lee ni envía el contenido real de tus archivos, solo nombres y metadatos.',
    'settings.persistHistory': 'Guardar historial en este equipo',
    'settings.persistHistoryNote': 'Desactivado: el historial desaparece al cerrar la app.',
    'settings.exportHistory': 'Exportar historial (.json/.csv)',
    'settings.exportSuccess': 'Exportado con éxito.',
    'settings.exportEmpty': 'Ningún bloqueo para exportar todavía.',
    'settings.clearHistory': 'Borrar historial ahora',

    'detail.title': 'Detalles del bloqueo',
    'detail.process': 'Proceso',
    'detail.pid': 'PID',
    'detail.localPort': 'Puerto local',
    'detail.domain': 'Dominio de destino',
    'detail.protocol': 'Protocolo',
    'detail.protocolValue': 'TCP/443 (TLS, bloqueado en el handshake)',
    'detail.timestamp': 'Fecha y hora',
    'detail.correlated': 'Acceso a archivo correlacionado',
    'detail.correlatedYes': 'Sí, en los 10s anteriores',
    'detail.correlatedNo': 'No',
    'detail.filePath': 'Archivo accedido',
    'detail.allow': 'Permitir siempre este programa',
    'detail.allowed': 'Siempre permitido',

    'blockMsg.correlated': 'Bloqueamos un intento de robo: {process} intentó enviar datos a {domain} justo después de acceder a tus archivos.',
    'blockMsg.suspicious': 'Bloqueamos una conexión sospechosa: {process} intentó contactar con {domain} sin autorización.',

    'notif.title': 'AntiGrabber bloqueó un intento',
    'notif.program': 'Programa: {process}',
    'notif.domain': 'Dominio: {domain}',
    'notif.correlatedNote': 'Acceso a archivo sensible detectado justo antes',

    'tray.active': 'AntiGrabber — protegiendo',
    'tray.block': 'AntiGrabber — bloqueo reciente',
    'tray.idle': 'AntiGrabber — inactivo',
    'tray.unseenSuffix': (v) => ` (${v.n} sin ver)`,

    'menu.open': 'Abrir AntiGrabber',
    'menu.quit': 'Salir',

    'export.dialogTitle': 'Exportar historial de bloqueos',

    'update.pillLabel': 'Actualización disponible',
    'update.title': 'Nueva versión: {version}',
    'update.noNotes': 'Sin notas de versión.',
    'update.updateNow': 'Actualizar ahora',
    'update.skipVersion': 'Ignorar esta versión',
    'update.remindLater': 'Recordar después',
    'update.phase.downloading': 'Descargando... {percent}%',
    'update.phase.verifying': 'Verificando integridad...',
    'update.phase.installing': 'Instalando (permiso de administrador)...',
    'update.phase.relaunching': 'Reiniciando AntiGrabber...',
    'update.phase.error': 'Falló la actualización. La versión actual sigue funcionando normalmente.',
    'settings.updates': 'Actualizaciones',
    'settings.checkNow': 'Verificar ahora',
    'settings.currentVersion': 'Versión instalada: {version}',
  },
};

function interpolate(str, vars) {
  if (!vars) return str;
  return str.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? ''));
}

function translate(lang, key, vars) {
  const table = dict[lang] || dict[DEFAULT_LANGUAGE];
  const entry = table[key] ?? dict[DEFAULT_LANGUAGE][key] ?? key;
  return typeof entry === 'function' ? entry(vars || {}) : interpolate(entry, vars);
}

function localeTag(lang) {
  return LOCALE_TAGS[lang] || LOCALE_TAGS[DEFAULT_LANGUAGE];
}

const AG_I18N = { translate, localeTag, DEFAULT_LANGUAGE, LANGUAGES: Object.keys(dict) };

if (typeof module === 'object' && module.exports) {
  module.exports = AG_I18N;
} else {
  window.AG_I18N = AG_I18N;
}
