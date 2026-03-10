import { createHash, randomUUID } from 'node:crypto';
import { getApp, getApps, initializeApp } from 'firebase/app';
import {
  addDoc,
  collection,
  doc,
  getDoc,
  getDocs,
  getFirestore,
  limit,
  orderBy,
  query,
  setDoc,
  updateDoc,
} from 'firebase/firestore';
import { getClientIp, sanitizeText, sendTelegramEventNotification } from './_telegram.js';

const FIREBASE_CONFIG = {
  apiKey: process.env.VITE_FIREBASE_API_KEY,
  authDomain: process.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.VITE_FIREBASE_PROJECT_ID,
  messagingSenderId: process.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.VITE_FIREBASE_APP_ID,
};

const hasFirebaseConfig = Object.values(FIREBASE_CONFIG).every(
  (value) => typeof value === 'string' && value.trim() !== '',
);

const getDb = () => {
  if (!hasFirebaseConfig) return null;
  const app = getApps().length > 0 ? getApp() : initializeApp(FIREBASE_CONFIG);
  return getFirestore(app);
};

const SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical'];
const SEVERITY_RANK = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const SECURITY_COLLECTIONS = {
  events: 'security_events',
  alerts: 'security_alerts',
  blockedIps: 'blocked_ips',
  auditLogs: 'admin_audit_logs',
  incidentActions: 'incident_actions',
};

const SETTINGS_COLLECTION = 'private_integrations';
const SETTINGS_DOC = 'security_center_v1';

const EVENT_BUFFER = globalThis.__securityEventBufferV2 || [];
globalThis.__securityEventBufferV2 = EVENT_BUFFER;

const TELEGRAM_ALERT_CACHE = globalThis.__securityTelegramCooldownV2 || new Map();
globalThis.__securityTelegramCooldownV2 = TELEGRAM_ALERT_CACHE;

const MEMORY_STORE = globalThis.__securityMemoryStoreV2 || {
  settings: null,
  events: [],
  alerts: [],
  blockedIps: new Map(),
  auditLogs: [],
  incidentActions: [],
};
globalThis.__securityMemoryStoreV2 = MEMORY_STORE;

const DEFAULT_SECURITY_SETTINGS = {
  enabled: true,
  retentionDays: 30,
  thresholds: {
    failedLoginBurst: 5,
    resetPasswordBurst: 4,
    mixedAuthAbuseBurst: 8,
    suspiciousRequestsBurst: 12,
    serverErrorsBurst: 10,
    ipRateAbusePerMinute: 90,
  },
  telegram: {
    enabled: true,
    minimumSeverity: 'medium',
    quietHoursEnabled: false,
    quietStart: '00:00',
    quietEnd: '07:00',
    mutedEventTypes: [],
    cooldownSeconds: 90,
    dedupeWindowSeconds: 300,
    batchWindowSeconds: 120,
    allowCommands: true,
    allowedTelegramUserIds: [],
    allowedChatIds: [],
    commandRateLimitPerMinute: 20,
  },
  controls: {
    loginEnabled: true,
    resetPasswordEnabled: true,
    heightenedProtection: false,
  },
  autoActions: {
    autoBlockOnCritical: false,
    autoBlockDurationMinutes: 30,
  },
};

const EVENT_TYPE_SEVERITY_HINT = {
  admin_login_success: 'info',
  admin_login_failed: 'medium',
  admin_login_failed_burst: 'high',
  admin_login_new_ip: 'medium',
  admin_login_new_device: 'medium',
  admin_access_denied: 'high',
  forgot_password_requested: 'medium',
  password_reset_requested: 'medium',
  password_reset_completed: 'medium',
  admin_settings_changed: 'high',
  telegram_settings_changed: 'high',
  suspicious_payload: 'high',
  rate_abuse: 'high',
  brute_force_suspected: 'high',
  credential_stuffing_suspected: 'critical',
  endpoint_auth_violation: 'high',
  server_error_spike: 'high',
  api_error: 'medium',
  route_probing: 'medium',
  telegram_command: 'medium',
  telegram_command_denied: 'high',
  security_alert_generated: 'high',
  order_created: 'info',
  order_status_changed: 'info',
  admin_action: 'low',
};

const normalizeSeverity = (value, fallback = 'medium') => {
  const normalized = String(value || fallback).trim().toLowerCase();
  return SEVERITY_LEVELS.includes(normalized) ? normalized : fallback;
};

const normalizeBoolean = (value, fallback = false) => {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return fallback;
};

const sanitizeIp = (ip) => sanitizeText(ip, 90) || 'unknown';

const docIdFromValue = (value) => createHash('sha256').update(String(value || '')).digest('hex').slice(0, 40);

const nowIso = () => new Date().toISOString();

const clampNumber = (value, min, max, fallback) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, numeric));
};

const normalizeStringArray = (value, maxItems = 40, maxLen = 80) => {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => sanitizeText(item, maxLen))
    .filter(Boolean)
    .slice(0, maxItems);
};

const normalizeTime = (value, fallback) => {
  const normalized = String(value || '').trim();
  if (!/^\d{2}:\d{2}$/.test(normalized)) return fallback;
  const [h, m] = normalized.split(':').map((entry) => Number(entry));
  if (!Number.isInteger(h) || !Number.isInteger(m) || h < 0 || h > 23 || m < 0 || m > 59) {
    return fallback;
  }
  return normalized;
};

const normalizeSecuritySettings = (rawValue) => {
  const source = rawValue && typeof rawValue === 'object' ? rawValue : {};
  const thresholdsSource = source.thresholds && typeof source.thresholds === 'object' ? source.thresholds : {};
  const telegramSource = source.telegram && typeof source.telegram === 'object' ? source.telegram : {};
  const controlsSource = source.controls && typeof source.controls === 'object' ? source.controls : {};
  const autoActionsSource = source.autoActions && typeof source.autoActions === 'object' ? source.autoActions : {};

  return {
    enabled: normalizeBoolean(source.enabled, DEFAULT_SECURITY_SETTINGS.enabled),
    retentionDays: clampNumber(source.retentionDays, 7, 180, DEFAULT_SECURITY_SETTINGS.retentionDays),
    thresholds: {
      failedLoginBurst: clampNumber(thresholdsSource.failedLoginBurst, 3, 30, DEFAULT_SECURITY_SETTINGS.thresholds.failedLoginBurst),
      resetPasswordBurst: clampNumber(thresholdsSource.resetPasswordBurst, 2, 30, DEFAULT_SECURITY_SETTINGS.thresholds.resetPasswordBurst),
      mixedAuthAbuseBurst: clampNumber(thresholdsSource.mixedAuthAbuseBurst, 4, 40, DEFAULT_SECURITY_SETTINGS.thresholds.mixedAuthAbuseBurst),
      suspiciousRequestsBurst: clampNumber(thresholdsSource.suspiciousRequestsBurst, 5, 80, DEFAULT_SECURITY_SETTINGS.thresholds.suspiciousRequestsBurst),
      serverErrorsBurst: clampNumber(thresholdsSource.serverErrorsBurst, 4, 60, DEFAULT_SECURITY_SETTINGS.thresholds.serverErrorsBurst),
      ipRateAbusePerMinute: clampNumber(thresholdsSource.ipRateAbusePerMinute, 20, 600, DEFAULT_SECURITY_SETTINGS.thresholds.ipRateAbusePerMinute),
    },
    telegram: {
      enabled: normalizeBoolean(telegramSource.enabled, DEFAULT_SECURITY_SETTINGS.telegram.enabled),
      minimumSeverity: normalizeSeverity(telegramSource.minimumSeverity, DEFAULT_SECURITY_SETTINGS.telegram.minimumSeverity),
      quietHoursEnabled: normalizeBoolean(telegramSource.quietHoursEnabled, DEFAULT_SECURITY_SETTINGS.telegram.quietHoursEnabled),
      quietStart: normalizeTime(telegramSource.quietStart, DEFAULT_SECURITY_SETTINGS.telegram.quietStart),
      quietEnd: normalizeTime(telegramSource.quietEnd, DEFAULT_SECURITY_SETTINGS.telegram.quietEnd),
      mutedEventTypes: normalizeStringArray(telegramSource.mutedEventTypes, 80, 80),
      cooldownSeconds: clampNumber(telegramSource.cooldownSeconds, 10, 3600, DEFAULT_SECURITY_SETTINGS.telegram.cooldownSeconds),
      dedupeWindowSeconds: clampNumber(telegramSource.dedupeWindowSeconds, 30, 7200, DEFAULT_SECURITY_SETTINGS.telegram.dedupeWindowSeconds),
      batchWindowSeconds: clampNumber(telegramSource.batchWindowSeconds, 30, 1800, DEFAULT_SECURITY_SETTINGS.telegram.batchWindowSeconds),
      allowCommands: normalizeBoolean(telegramSource.allowCommands, DEFAULT_SECURITY_SETTINGS.telegram.allowCommands),
      allowedTelegramUserIds: normalizeStringArray(telegramSource.allowedTelegramUserIds, 80, 30),
      allowedChatIds: normalizeStringArray(telegramSource.allowedChatIds, 80, 40),
      commandRateLimitPerMinute: clampNumber(telegramSource.commandRateLimitPerMinute, 5, 240, DEFAULT_SECURITY_SETTINGS.telegram.commandRateLimitPerMinute),
    },
    controls: {
      loginEnabled: normalizeBoolean(controlsSource.loginEnabled, DEFAULT_SECURITY_SETTINGS.controls.loginEnabled),
      resetPasswordEnabled: normalizeBoolean(controlsSource.resetPasswordEnabled, DEFAULT_SECURITY_SETTINGS.controls.resetPasswordEnabled),
      heightenedProtection: normalizeBoolean(controlsSource.heightenedProtection, DEFAULT_SECURITY_SETTINGS.controls.heightenedProtection),
    },
    autoActions: {
      autoBlockOnCritical: normalizeBoolean(autoActionsSource.autoBlockOnCritical, DEFAULT_SECURITY_SETTINGS.autoActions.autoBlockOnCritical),
      autoBlockDurationMinutes: clampNumber(autoActionsSource.autoBlockDurationMinutes, 5, 720, DEFAULT_SECURITY_SETTINGS.autoActions.autoBlockDurationMinutes),
    },
  };
};

const getSettingsRef = (db) => doc(db, SETTINGS_COLLECTION, SETTINGS_DOC);

const getSecuritySettings = async () => {
  const db = getDb();
  if (!db) {
    const normalized = normalizeSecuritySettings(MEMORY_STORE.settings || DEFAULT_SECURITY_SETTINGS);
    MEMORY_STORE.settings = normalized;
    return normalized;
  }

  try {
    const snapshot = await getDoc(getSettingsRef(db));
    if (!snapshot.exists()) {
      const defaults = normalizeSecuritySettings(DEFAULT_SECURITY_SETTINGS);
      await setDoc(getSettingsRef(db), { ...defaults, createdAt: nowIso(), updatedAt: nowIso() }, { merge: true });
      return defaults;
    }

    return normalizeSecuritySettings(snapshot.data() || {});
  } catch {
    return normalizeSecuritySettings(DEFAULT_SECURITY_SETTINGS);
  }
};

const saveSecuritySettings = async (incoming, actor = {}) => {
  const current = await getSecuritySettings();
  const merged = normalizeSecuritySettings({
    ...current,
    ...(incoming && typeof incoming === 'object' ? incoming : {}),
  });

  const db = getDb();
  if (!db) {
    MEMORY_STORE.settings = merged;
    return merged;
  }

  await setDoc(
    getSettingsRef(db),
    {
      ...merged,
      updatedAt: nowIso(),
      updatedBy: sanitizeText(actor.email, 140),
    },
    { merge: true },
  );

  return merged;
};

const pushToEventBuffer = (event) => {
  EVENT_BUFFER.push({
    time: Date.now(),
    type: event.eventType,
    severity: event.severity,
    ip: event.ipAddress,
  });

  const maxAge = Date.now() - 1000 * 60 * 90;
  while (EVENT_BUFFER.length > 0 && EVENT_BUFFER[0].time < maxAge) {
    EVENT_BUFFER.shift();
  }
  if (EVENT_BUFFER.length > 8000) {
    EVENT_BUFFER.splice(0, EVENT_BUFFER.length - 8000);
  }
};

const countBufferedEvents = ({ types = [], ip = '', withinMs = 10 * 60 * 1000 }) => {
  const typeSet = new Set(types.map((entry) => String(entry)));
  const minTime = Date.now() - withinMs;
  return EVENT_BUFFER.reduce((count, item) => {
    if (item.time < minTime) return count;
    if (ip && item.ip !== ip) return count;
    if (typeSet.size > 0 && !typeSet.has(item.type)) return count;
    return count + 1;
  }, 0);
};

const severityToRiskBase = (severity) => {
  switch (severity) {
    case 'critical':
      return 90;
    case 'high':
      return 75;
    case 'medium':
      return 55;
    case 'low':
      return 35;
    default:
      return 20;
  }
};

const computeRiskScore = ({ severity, repeatedCount, hasSuspiciousPattern }) => {
  const base = severityToRiskBase(severity);
  const repeatedBonus = Math.min(25, Math.max(0, (Number(repeatedCount) - 1) * 4));
  const suspiciousBonus = hasSuspiciousPattern ? 12 : 0;
  return Math.min(100, base + repeatedBonus + suspiciousBonus);
};

const buildAlertFingerprint = (event, hint = '') => {
  const key = [
    sanitizeText(event.eventType, 80),
    sanitizeText(event.ipAddress, 70),
    sanitizeText(event.source, 50),
    sanitizeText(hint, 80),
  ]
    .filter(Boolean)
    .join('|');

  return createHash('sha1').update(key).digest('hex').slice(0, 24);
};

const shouldSuppressForQuietHours = (settings) => {
  const telegram = settings.telegram;
  if (!telegram.quietHoursEnabled) return false;

  const now = new Date();
  const nowMinutes = now.getHours() * 60 + now.getMinutes();
  const [startH, startM] = telegram.quietStart.split(':').map((entry) => Number(entry));
  const [endH, endM] = telegram.quietEnd.split(':').map((entry) => Number(entry));
  const startMinutes = startH * 60 + startM;
  const endMinutes = endH * 60 + endM;

  if (startMinutes === endMinutes) return false;
  if (startMinutes < endMinutes) {
    return nowMinutes >= startMinutes && nowMinutes < endMinutes;
  }

  return nowMinutes >= startMinutes || nowMinutes < endMinutes;
};

const shouldSendTelegramForAlert = (alert, settings) => {
  const telegram = settings.telegram;
  if (!telegram.enabled) return false;

  if (SEVERITY_RANK[alert.severity] < SEVERITY_RANK[telegram.minimumSeverity]) {
    return false;
  }

  if (shouldSuppressForQuietHours(settings) && alert.severity !== 'critical') {
    return false;
  }

  if (telegram.mutedEventTypes.includes(alert.eventType)) {
    return false;
  }

  const cacheKey = alert.fingerprint;
  const now = Date.now();
  const lastSentAt = Number(TELEGRAM_ALERT_CACHE.get(cacheKey) || 0);
  const cooldownMs = Number(telegram.cooldownSeconds) * 1000;

  if (now - lastSentAt < cooldownMs) {
    return false;
  }

  TELEGRAM_ALERT_CACHE.set(cacheKey, now);
  return true;
};

const formatTelegramAlertMessage = (alert) => alert;

const collectionRef = (db, key) => collection(db, SECURITY_COLLECTIONS[key]);

const writeEventRecord = async (record) => {
  const db = getDb();

  if (!db) {
    const inMemory = { ...record, id: randomUUID() };
    MEMORY_STORE.events.unshift(inMemory);
    MEMORY_STORE.events = MEMORY_STORE.events.slice(0, 2500);
    return inMemory;
  }

  const ref = await addDoc(collectionRef(db, 'events'), record);
  return {
    ...record,
    id: ref.id,
  };
};

const writeAlertRecord = async (record) => {
  const db = getDb();

  if (!db) {
    const inMemory = { ...record, id: randomUUID() };
    MEMORY_STORE.alerts.unshift(inMemory);
    MEMORY_STORE.alerts = MEMORY_STORE.alerts.slice(0, 1200);
    return inMemory;
  }

  const ref = await addDoc(collectionRef(db, 'alerts'), record);
  return {
    ...record,
    id: ref.id,
  };
};

const updateAlertRecord = async (id, patch) => {
  const db = getDb();
  if (!db) {
    MEMORY_STORE.alerts = MEMORY_STORE.alerts.map((entry) => (entry.id === id ? { ...entry, ...patch } : entry));
    return;
  }

  await updateDoc(doc(db, SECURITY_COLLECTIONS.alerts, id), patch);
};

const fetchRecentAlerts = async (maxItems = 300) => {
  const db = getDb();

  if (!db) {
    return MEMORY_STORE.alerts.slice(0, maxItems);
  }

  const snapshot = await getDocs(
    query(collectionRef(db, 'alerts'), orderBy('lastSeenAtEpoch', 'desc'), limit(maxItems)),
  );

  return snapshot.docs.map((entry) => ({ id: entry.id, ...(entry.data() || {}) }));
};

const maybePromoteToAlert = async (event, settings) => {
  const thresholds = settings.thresholds;
  const repeatedFailedLogins = countBufferedEvents({
    types: ['admin_login_failed', 'admin_access_denied'],
    ip: event.ipAddress,
    withinMs: 10 * 60 * 1000,
  });

  const repeatedResetRequests = countBufferedEvents({
    types: ['forgot_password_requested', 'password_reset_requested'],
    ip: event.ipAddress,
    withinMs: 15 * 60 * 1000,
  });

  const suspiciousBurst = countBufferedEvents({
    types: ['suspicious_payload', 'route_probing', 'endpoint_auth_violation', 'rate_abuse'],
    ip: event.ipAddress,
    withinMs: 10 * 60 * 1000,
  });

  const serverErrors = countBufferedEvents({
    types: ['api_error', 'server_error_spike'],
    withinMs: 10 * 60 * 1000,
  });

  let shouldAlert = false;
  let alertSeverity = event.severity;
  let summary = event.summary;
  let reason = '';

  if (event.eventType === 'admin_login_failed' && repeatedFailedLogins >= thresholds.failedLoginBurst) {
    shouldAlert = true;
    alertSeverity = repeatedFailedLogins >= thresholds.failedLoginBurst * 2 ? 'critical' : 'high';
    reason = 'failed_login_burst';
    summary = `Repeated admin login failures from the same IP (${repeatedFailedLogins} in 10m).`;
  }

  if (repeatedResetRequests >= thresholds.resetPasswordBurst) {
    shouldAlert = true;
    alertSeverity = SEVERITY_RANK[alertSeverity] < SEVERITY_RANK.high ? 'high' : alertSeverity;
    reason = reason || 'reset_password_abuse';
    summary = `Password reset requests are spiking (${repeatedResetRequests} in 15m).`;
  }

  if (repeatedFailedLogins + repeatedResetRequests >= thresholds.mixedAuthAbuseBurst) {
    shouldAlert = true;
    alertSeverity = 'critical';
    reason = 'mixed_auth_abuse';
    summary = 'Combined failed login and reset-password activity indicates potential credential attack.';
  }

  if (suspiciousBurst >= thresholds.suspiciousRequestsBurst) {
    shouldAlert = true;
    alertSeverity = 'critical';
    reason = reason || 'suspicious_request_burst';
    summary = `Suspicious requests burst detected (${suspiciousBurst} in 10m).`;
  }

  if (event.eventType === 'suspicious_payload' || event.eventType === 'credential_stuffing_suspected') {
    shouldAlert = true;
    alertSeverity = 'critical';
    reason = reason || 'malicious_payload';
  }

  if (serverErrors >= thresholds.serverErrorsBurst && (event.eventType === 'api_error' || event.eventType === 'server_error_spike')) {
    shouldAlert = true;
    alertSeverity = SEVERITY_RANK[event.severity] >= SEVERITY_RANK.high ? event.severity : 'high';
    reason = reason || 'server_error_spike';
    summary = `Server/API errors increased unexpectedly (${serverErrors} in 10m).`;
  }

  if (!shouldAlert && SEVERITY_RANK[event.severity] >= SEVERITY_RANK.high) {
    shouldAlert = true;
    reason = reason || 'high_severity_event';
  }

  if (!shouldAlert) {
    return null;
  }

  const fingerprint = buildAlertFingerprint(event, reason);
  const recentAlerts = await fetchRecentAlerts(250);
  const dedupeWindowMs = settings.telegram.dedupeWindowSeconds * 1000;
  const currentTs = Date.now();

  const existing = recentAlerts.find((entry) => {
    if (entry.fingerprint !== fingerprint) return false;
    if (entry.status === 'archived' || entry.status === 'resolved') return false;
    const lastSeen = Number(entry.lastSeenAtEpoch || 0);
    return currentTs - lastSeen <= dedupeWindowMs;
  });

  const repeatedCount = Math.max(repeatedFailedLogins, repeatedResetRequests, suspiciousBurst, 1);

  const riskScore = computeRiskScore({
    severity: alertSeverity,
    repeatedCount,
    hasSuspiciousPattern: reason !== 'high_severity_event',
  });

  if (existing) {
    const patch = {
      lastSeenAt: nowIso(),
      lastSeenAtEpoch: currentTs,
      count: Number(existing.count || 1) + 1,
      severity: SEVERITY_RANK[existing.severity] >= SEVERITY_RANK[alertSeverity] ? existing.severity : alertSeverity,
      summary,
      riskScore: Math.max(Number(existing.riskScore || 0), riskScore),
      updatedAt: nowIso(),
    };

    await updateAlertRecord(existing.id, patch);
    return {
      ...existing,
      ...patch,
      id: existing.id,
      eventType: existing.eventType || event.eventType,
      source: existing.source || event.source,
      ipAddress: existing.ipAddress || event.ipAddress,
      userEmail: existing.userEmail || event.userEmail,
      endpoint: existing.endpoint || event.endpoint,
      metadata: existing.metadata || event.metadata,
    };
  }

  const alertRecord = {
    eventType: event.eventType,
    source: event.source,
    severity: alertSeverity,
    status: 'unresolved',
    read: false,
    archived: false,
    summary,
    reason,
    fingerprint,
    count: 1,
    riskScore,
    ipAddress: event.ipAddress,
    endpoint: event.endpoint,
    userEmail: event.userEmail,
    userId: event.userId,
    metadata: event.metadata,
    labels: [],
    notes: [],
    createdAt: nowIso(),
    createdAtEpoch: currentTs,
    lastSeenAt: nowIso(),
    lastSeenAtEpoch: currentTs,
    updatedAt: nowIso(),
  };

  return writeAlertRecord(alertRecord);
};

const logSecurityEvent = async (input = {}) => {
  const safeInput = input && typeof input === 'object' ? input : {};
  const severity = normalizeSeverity(
    safeInput.severity,
    EVENT_TYPE_SEVERITY_HINT[safeInput.eventType] || 'medium',
  );

  const eventRecord = {
    eventType: sanitizeText(safeInput.eventType, 80) || 'unknown_event',
    severity,
    source: sanitizeText(safeInput.source, 80) || 'system',
    status: sanitizeText(safeInput.status, 40) || 'captured',
    summary: sanitizeText(safeInput.summary || safeInput.message, 260) || 'Security event recorded.',
    ipAddress: sanitizeIp(safeInput.ipAddress),
    endpoint: sanitizeText(safeInput.endpoint, 160),
    userId: sanitizeText(safeInput.userId, 80),
    userEmail: sanitizeText(safeInput.userEmail, 140),
    metadata: safeInput.metadata && typeof safeInput.metadata === 'object' ? safeInput.metadata : {},
    actor: {
      type: sanitizeText(safeInput.actor?.type, 40),
      id: sanitizeText(safeInput.actor?.id, 80),
      email: sanitizeText(safeInput.actor?.email, 140),
      role: sanitizeText(safeInput.actor?.role, 40),
    },
    createdAt: nowIso(),
    createdAtEpoch: Date.now(),
  };

  const writtenEvent = await writeEventRecord(eventRecord);
  pushToEventBuffer(eventRecord);

  const settings = await getSecuritySettings();
  if (!settings.enabled) {
    return { event: writtenEvent, alert: null, notified: false };
  }

  const alert = await maybePromoteToAlert({ ...eventRecord, id: writtenEvent.id }, settings);

  let notified = false;
  if (alert && shouldSendTelegramForAlert(alert, settings)) {
    const sendResult = await sendTelegramEventNotification({
      eventType: 'security_alert',
      message: formatTelegramAlertMessage(alert),
      payload: alert,
    });
    notified = Boolean(sendResult?.ok && sendResult?.delivered);

    if (!sendResult?.ok) {
      await writeEventRecord({
        eventType: 'telegram_alert_failed',
        severity: 'medium',
        source: 'security_center',
        status: 'failed',
        summary: sanitizeText(sendResult?.error || 'Failed to deliver Telegram security alert', 220),
        ipAddress: 'internal',
        endpoint: '/api/telegram-notify',
        userId: '',
        userEmail: '',
        metadata: {
          alertId: alert.id,
          fingerprint: alert.fingerprint,
        },
        actor: { type: 'system', id: '', email: '', role: '' },
        createdAt: nowIso(),
        createdAtEpoch: Date.now(),
      });
    }
  }

  return { event: writtenEvent, alert, notified };
};

const logAdminAudit = async ({ action, actorEmail, actorUid, ipAddress, targetType, targetId, before, after, metadata }) => {
  const record = {
    action: sanitizeText(action, 120) || 'admin_action',
    actorEmail: sanitizeText(actorEmail, 140),
    actorUid: sanitizeText(actorUid, 80),
    ipAddress: sanitizeIp(ipAddress),
    targetType: sanitizeText(targetType, 100),
    targetId: sanitizeText(targetId, 120),
    before: before && typeof before === 'object' ? before : null,
    after: after && typeof after === 'object' ? after : null,
    metadata: metadata && typeof metadata === 'object' ? metadata : {},
    createdAt: nowIso(),
    createdAtEpoch: Date.now(),
  };

  const db = getDb();
  if (!db) {
    const inMemory = { ...record, id: randomUUID() };
    MEMORY_STORE.auditLogs.unshift(inMemory);
    MEMORY_STORE.auditLogs = MEMORY_STORE.auditLogs.slice(0, 3000);
    return inMemory;
  }

  const ref = await addDoc(collectionRef(db, 'auditLogs'), record);
  return { ...record, id: ref.id };
};

const listRecordsFromCollection = async (key, maxItems = 300) => {
  const db = getDb();

  if (!db) {
    if (key === 'events') return MEMORY_STORE.events.slice(0, maxItems);
    if (key === 'alerts') return MEMORY_STORE.alerts.slice(0, maxItems);
    if (key === 'auditLogs') return MEMORY_STORE.auditLogs.slice(0, maxItems);
    if (key === 'incidentActions') return MEMORY_STORE.incidentActions.slice(0, maxItems);
    return [];
  }

  const snapshot = await getDocs(query(collectionRef(db, key), orderBy('createdAtEpoch', 'desc'), limit(maxItems)));
  return snapshot.docs.map((entry) => ({ id: entry.id, ...(entry.data() || {}) }));
};

const filterByDateRange = (items, fromDate, toDate) => {
  const fromMs = fromDate ? new Date(fromDate).getTime() : 0;
  const toMs = toDate ? new Date(toDate).getTime() : 0;

  return items.filter((item) => {
    const created = Number(item.createdAtEpoch || 0) || new Date(item.createdAt || 0).getTime();
    if (fromMs && created < fromMs) return false;
    if (toMs && created > toMs + 24 * 60 * 60 * 1000 - 1) return false;
    return true;
  });
};

const listSecurityEvents = async (filters = {}) => {
  const all = await listRecordsFromCollection('events', 800);
  const queryText = sanitizeText(filters.query, 100).toLowerCase();
  const severityRaw = String(filters.severity || '').trim();
  const severity = severityRaw ? normalizeSeverity(severityRaw, '') : '';
  const eventType = sanitizeText(filters.eventType, 80);
  const ip = sanitizeText(filters.ip, 90);
  const status = sanitizeText(filters.status, 40);

  const filtered = filterByDateRange(all, filters.fromDate, filters.toDate).filter((item) => {
    if (severity && item.severity !== severity) return false;
    if (eventType && item.eventType !== eventType) return false;
    if (ip && item.ipAddress !== ip) return false;
    if (status && item.status !== status) return false;

    if (queryText) {
      const haystack = [item.eventType, item.summary, item.source, item.userEmail, item.endpoint, item.ipAddress]
        .map((value) => String(value || '').toLowerCase())
        .join(' ');

      if (!haystack.includes(queryText)) return false;
    }

    return true;
  });

  return filtered;
};

const listSecurityAlerts = async (filters = {}) => {
  const all = await listRecordsFromCollection('alerts', 600);
  const queryText = sanitizeText(filters.query, 120).toLowerCase();
  const severityRaw = String(filters.severity || '').trim();
  const severity = severityRaw ? normalizeSeverity(severityRaw, '') : '';
  const status = sanitizeText(filters.status, 40);
  const read = String(filters.read || '').trim();
  const source = sanitizeText(filters.source, 80);

  const filtered = filterByDateRange(all, filters.fromDate, filters.toDate).filter((item) => {
    if (severity && item.severity !== severity) return false;
    if (status && item.status !== status) return false;
    if (source && item.source !== source) return false;
    if (read === 'true' && !item.read) return false;
    if (read === 'false' && item.read) return false;

    if (queryText) {
      const haystack = [
        item.eventType,
        item.summary,
        item.source,
        item.userEmail,
        item.ipAddress,
        ...(Array.isArray(item.labels) ? item.labels : []),
      ]
        .map((value) => String(value || '').toLowerCase())
        .join(' ');
      if (!haystack.includes(queryText)) return false;
    }

    return true;
  });

  return filtered;
};

const listAuditTrail = async (filters = {}) => {
  const all = await listRecordsFromCollection('auditLogs', 800);
  const queryText = sanitizeText(filters.query, 100).toLowerCase();

  return filterByDateRange(all, filters.fromDate, filters.toDate).filter((item) => {
    if (!queryText) return true;
    const haystack = [item.action, item.actorEmail, item.targetType, item.targetId, item.ipAddress]
      .map((value) => String(value || '').toLowerCase())
      .join(' ');
    return haystack.includes(queryText);
  });
};

const setAlertState = async ({ alertId, patch = {}, actor = {} }) => {
  const cleanAlertId = sanitizeText(alertId, 80);
  if (!cleanAlertId) throw new Error('alertId is required');

  const updatePatch = {
    ...patch,
    updatedAt: nowIso(),
    updatedBy: sanitizeText(actor.email, 140),
  };

  if (patch.status === 'resolved') {
    updatePatch.resolvedAt = nowIso();
    updatePatch.resolvedBy = sanitizeText(actor.email, 140);
  }

  await updateAlertRecord(cleanAlertId, updatePatch);

  await logAdminAudit({
    action: `alert_${patch.status || 'updated'}`,
    actorEmail: actor.email,
    actorUid: actor.uid,
    ipAddress: actor.ipAddress,
    targetType: 'security_alert',
    targetId: cleanAlertId,
    metadata: patch,
  });
};

const blockIpAddress = async ({ ipAddress, reason, actor }) => {
  const normalizedIp = sanitizeIp(ipAddress);
  if (!normalizedIp || normalizedIp === 'unknown') {
    throw new Error('Invalid IP address.');
  }

  const entry = {
    ipAddress: normalizedIp,
    status: 'blocked',
    reason: sanitizeText(reason, 220) || 'Manual security action',
    blockedAt: nowIso(),
    blockedBy: sanitizeText(actor?.email, 140),
    createdAt: nowIso(),
    createdAtEpoch: Date.now(),
    updatedAt: nowIso(),
  };

  const db = getDb();
  if (!db) {
    MEMORY_STORE.blockedIps.set(docIdFromValue(normalizedIp), entry);
  } else {
    await setDoc(doc(db, SECURITY_COLLECTIONS.blockedIps, docIdFromValue(normalizedIp)), entry, { merge: true });
  }

  await logAdminAudit({
    action: 'block_ip',
    actorEmail: actor?.email,
    actorUid: actor?.uid,
    ipAddress: actor?.ipAddress,
    targetType: 'ip_address',
    targetId: normalizedIp,
    metadata: { reason: entry.reason },
  });

  await logSecurityEvent({
    eventType: 'admin_action',
    severity: 'high',
    source: 'incident_response',
    summary: `IP ${normalizedIp} was blocked from Security Center.`,
    ipAddress: actor?.ipAddress || 'internal',
    userEmail: actor?.email || '',
    metadata: {
      blockedIp: normalizedIp,
      reason: entry.reason,
    },
  });

  return entry;
};

const unblockIpAddress = async ({ ipAddress, actor }) => {
  const normalizedIp = sanitizeIp(ipAddress);
  if (!normalizedIp || normalizedIp === 'unknown') {
    throw new Error('Invalid IP address.');
  }

  const patch = {
    ipAddress: normalizedIp,
    status: 'unblocked',
    unblockedAt: nowIso(),
    unblockedBy: sanitizeText(actor?.email, 140),
    updatedAt: nowIso(),
  };

  const db = getDb();
  if (!db) {
    const current = MEMORY_STORE.blockedIps.get(docIdFromValue(normalizedIp)) || {};
    MEMORY_STORE.blockedIps.set(docIdFromValue(normalizedIp), { ...current, ...patch });
  } else {
    await setDoc(doc(db, SECURITY_COLLECTIONS.blockedIps, docIdFromValue(normalizedIp)), patch, { merge: true });
  }

  await logAdminAudit({
    action: 'unblock_ip',
    actorEmail: actor?.email,
    actorUid: actor?.uid,
    ipAddress: actor?.ipAddress,
    targetType: 'ip_address',
    targetId: normalizedIp,
  });

  return patch;
};

const listBlockedIps = async () => {
  const db = getDb();

  if (!db) {
    return Array.from(MEMORY_STORE.blockedIps.values())
      .sort((a, b) => Number(b.createdAtEpoch || 0) - Number(a.createdAtEpoch || 0))
      .slice(0, 400);
  }

  const snapshot = await getDocs(query(collectionRef(db, 'blockedIps'), orderBy('createdAtEpoch', 'desc'), limit(400)));
  return snapshot.docs.map((entry) => ({ id: entry.id, ...(entry.data() || {}) }));
};

const isIpBlocked = async (ipAddress) => {
  const normalizedIp = sanitizeIp(ipAddress);
  if (!normalizedIp || normalizedIp === 'unknown') return false;

  const db = getDb();
  if (!db) {
    const entry = MEMORY_STORE.blockedIps.get(docIdFromValue(normalizedIp));
    return Boolean(entry && entry.status === 'blocked');
  }

  const snapshot = await getDoc(doc(db, SECURITY_COLLECTIONS.blockedIps, docIdFromValue(normalizedIp)));
  if (!snapshot.exists()) return false;

  const entry = snapshot.data() || {};
  return entry.status === 'blocked';
};

const addIncidentAction = async ({ action, actor, payload = {} }) => {
  const record = {
    action: sanitizeText(action, 120),
    actorEmail: sanitizeText(actor?.email, 140),
    actorUid: sanitizeText(actor?.uid, 80),
    actorIp: sanitizeIp(actor?.ipAddress),
    payload: payload && typeof payload === 'object' ? payload : {},
    createdAt: nowIso(),
    createdAtEpoch: Date.now(),
  };

  const db = getDb();
  if (!db) {
    const entry = { ...record, id: randomUUID() };
    MEMORY_STORE.incidentActions.unshift(entry);
    MEMORY_STORE.incidentActions = MEMORY_STORE.incidentActions.slice(0, 1000);
    return entry;
  }

  const ref = await addDoc(collectionRef(db, 'incidentActions'), record);
  return { ...record, id: ref.id };
};

const getPublicSecurityStatus = async () => {
  const settings = await getSecuritySettings();
  return {
    loginEnabled: Boolean(settings.controls.loginEnabled),
    resetPasswordEnabled: Boolean(settings.controls.resetPasswordEnabled),
    heightenedProtection: Boolean(settings.controls.heightenedProtection),
  };
};

const getSecurityOverview = async () => {
  const [events, alerts, blockedIps, settings] = await Promise.all([
    listSecurityEvents({}),
    listSecurityAlerts({}),
    listBlockedIps(),
    getSecuritySettings(),
  ]);

  const now = Date.now();
  const dayAgo = now - 24 * 60 * 60 * 1000;
  const weekAgo = now - 7 * 24 * 60 * 60 * 1000;

  const dayEvents = events.filter((entry) => Number(entry.createdAtEpoch || 0) >= dayAgo);
  const dayAlerts = alerts.filter((entry) => Number(entry.createdAtEpoch || 0) >= dayAgo);
  const weekEvents = events.filter((entry) => Number(entry.createdAtEpoch || 0) >= weekAgo);

  const failedLoginsToday = dayEvents.filter((entry) => entry.eventType === 'admin_login_failed').length;
  const resetRequestsToday = dayEvents.filter((entry) => entry.eventType === 'forgot_password_requested' || entry.eventType === 'password_reset_requested').length;

  const unresolvedAlerts = alerts.filter((entry) => entry.status !== 'resolved' && !entry.archived);
  const criticalUnresolved = unresolvedAlerts.filter((entry) => entry.severity === 'critical').length;

  const riskLevel = criticalUnresolved > 0
    ? 'critical'
    : unresolvedAlerts.some((entry) => entry.severity === 'high')
    ? 'high'
    : unresolvedAlerts.length > 0
    ? 'medium'
    : 'low';

  const hourlyBuckets = Array.from({ length: 24 }).map((_, index) => {
    const start = now - (23 - index) * 60 * 60 * 1000;
    const end = start + 60 * 60 * 1000;
    const count = dayEvents.filter((entry) => {
      const ts = Number(entry.createdAtEpoch || 0);
      return ts >= start && ts < end;
    }).length;

    return {
      label: new Date(start).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }),
      count,
    };
  });

  return {
    metrics: {
      alertsToday: dayAlerts.length,
      failedLoginsToday,
      resetRequestsToday,
      blockedIpsCount: blockedIps.filter((entry) => entry.status === 'blocked').length,
      unresolvedAlerts: unresolvedAlerts.length,
      riskLevel,
      telegramEnabled: Boolean(settings.telegram.enabled),
      commandControlEnabled: Boolean(settings.telegram.allowCommands),
    },
    trends: {
      last24Hours: hourlyBuckets,
      eventsLast7Days: weekEvents.length,
    },
    latestCriticalAlerts: unresolvedAlerts
      .filter((entry) => entry.severity === 'critical' || entry.severity === 'high')
      .slice(0, 8),
    latestEvents: events.slice(0, 12),
  };
};

const toCsv = (items = []) => {
  if (!Array.isArray(items) || items.length === 0) return '';

  const headers = Object.keys(items[0]);
  const lines = [headers.join(',')];

  for (const row of items) {
    const values = headers.map((key) => {
      const value = row[key];
      const normalized = typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
      return `"${normalized.replaceAll('"', '""')}"`;
    });
    lines.push(values.join(','));
  }

  return lines.join('\n');
};

const buildEventFromRequest = ({ req, eventType, severity, summary, source, status, metadata, user }) => {
  const ipAddress = getClientIp(req);
  return {
    eventType,
    severity,
    summary,
    source,
    status,
    ipAddress,
    endpoint: sanitizeText(req.url, 180),
    userId: sanitizeText(user?.uid, 80),
    userEmail: sanitizeText(user?.email, 140),
    metadata: {
      ...(metadata && typeof metadata === 'object' ? metadata : {}),
      userAgent: sanitizeText(req.headers['user-agent'], 180),
    },
    actor: {
      type: user?.uid ? 'admin' : 'public',
      id: sanitizeText(user?.uid, 80),
      email: sanitizeText(user?.email, 140),
      role: user?.uid ? 'admin' : 'guest',
    },
  };
};

export {
  DEFAULT_SECURITY_SETTINGS,
  EVENT_TYPE_SEVERITY_HINT,
  SEVERITY_LEVELS,
  SEVERITY_RANK,
  SECURITY_COLLECTIONS,
  addIncidentAction,
  blockIpAddress,
  buildEventFromRequest,
  getPublicSecurityStatus,
  getSecurityOverview,
  getSecuritySettings,
  isIpBlocked,
  listAuditTrail,
  listBlockedIps,
  listSecurityAlerts,
  listSecurityEvents,
  logAdminAudit,
  logSecurityEvent,
  normalizeSecuritySettings,
  normalizeSeverity,
  saveSecuritySettings,
  sanitizeIp,
  setAlertState,
  toCsv,
  unblockIpAddress,
};
