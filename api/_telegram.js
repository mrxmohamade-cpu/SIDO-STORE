import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { getApp, getApps, initializeApp } from 'firebase/app';
import { doc, getDoc, getFirestore, setDoc } from 'firebase/firestore';

const TELEGRAM_COLLECTION = 'private_integrations';
const TELEGRAM_DOC_ID = 'telegram_v1';
const RATE_LIMIT_STORE = globalThis.__telegramRateLimitStore || new Map();
globalThis.__telegramRateLimitStore = RATE_LIMIT_STORE;

const DEFAULT_NOTIFICATIONS = {
  newOrder: true,
  orderStatus: true,
  systemErrors: false,
  adminActions: true,
};

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

const sanitizeText = (value, maxLength = 180) =>
  String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);

const escapeHtml = (value = '') =>
  String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');

const parseRequestBody = (body) => {
  if (!body) return null;
  if (typeof body === 'object') return body;
  if (typeof body !== 'string') return null;

  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
};

const getClientIp = (req) => {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
    return forwardedFor.split(',')[0].trim();
  }

  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string' && realIp.trim()) {
    return realIp.trim();
  }

  return req.socket?.remoteAddress || 'unknown';
};

const isRateLimited = (scope, ip, maxRequests, windowMs) => {
  const now = Date.now();
  const storeKey = `${scope}:${String(ip || 'unknown')}`;
  const windowStart = now - windowMs;

  for (const [key, timestamps] of RATE_LIMIT_STORE.entries()) {
    const active = timestamps.filter((ts) => ts > windowStart);
    if (active.length > 0) {
      RATE_LIMIT_STORE.set(key, active);
    } else {
      RATE_LIMIT_STORE.delete(key);
    }
  }

  const current = RATE_LIMIT_STORE.get(storeKey) || [];
  if (current.length >= maxRequests) return true;

  current.push(now);
  RATE_LIMIT_STORE.set(storeKey, current);
  return false;
};

const getAllowedAdminEmails = () => {
  const configured = String(process.env.ADMIN_ALLOWED_EMAILS || '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  const fallback = [
    String(process.env.VITE_ADMIN_RECOVERY_EMAIL || '').trim().toLowerCase(),
    String(process.env.VITE_ADMIN_EMAIL || '').trim().toLowerCase(),
  ].filter(Boolean);

  return new Set([...configured, ...fallback]);
};

const extractBearerToken = (authorizationHeader) => {
  const header = String(authorizationHeader || '');
  if (!header.startsWith('Bearer ')) return '';
  return header.slice(7).trim();
};

const verifyAdminRequest = async (req) => {
  const idToken = extractBearerToken(req.headers.authorization);
  if (!idToken) {
    return { ok: false, status: 401, error: 'Unauthorized.' };
  }

  const apiKey = String(process.env.VITE_FIREBASE_API_KEY || '').trim();
  if (!apiKey) {
    return { ok: false, status: 500, error: 'Server configuration is missing.' };
  }

  try {
    const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken }),
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      return { ok: false, status: 401, error: 'Unauthorized.' };
    }

    const user = Array.isArray(payload.users) ? payload.users[0] : null;
    const email = String(user?.email || '').trim().toLowerCase();
    if (!email) {
      return { ok: false, status: 401, error: 'Unauthorized.' };
    }

    const allowed = getAllowedAdminEmails();
    if (allowed.size > 0 && !allowed.has(email)) {
      return { ok: false, status: 403, error: 'Forbidden.' };
    }

    return {
      ok: true,
      value: {
        email,
        uid: String(user?.localId || ''),
      },
    };
  } catch {
    return { ok: false, status: 500, error: 'Authorization service unavailable.' };
  }
};

const createTelegramError = (code, message) => {
  const error = new Error(message);
  error.code = code;
  return error;
};

const getTelegramErrorCode = (error) => sanitizeText(error?.code, 60).toLowerCase();

const getEncryptionSecret = () => {
  const configured = String(process.env.TELEGRAM_ENCRYPTION_SECRET || '').trim();
  if (configured) return configured;

  const compatibilitySeed = [
    String(process.env.ADMIN_ALLOWED_EMAILS || '').trim(),
    String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim(),
    String(process.env.VITE_FIREBASE_API_KEY || '').trim(),
    String(process.env.VITE_FIREBASE_PROJECT_ID || '').trim(),
    String(process.env.VITE_ADMIN_EMAIL || '').trim(),
    String(process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL || '').trim(),
  ]
    .filter(Boolean)
    .join('|');

  if (compatibilitySeed) {
    return `compat-secret:${compatibilitySeed}`;
  }

  if (process.env.NODE_ENV !== 'production') {
    const projectScope = String(process.env.VITE_FIREBASE_PROJECT_ID || 'store-dz-local').trim();
    return `dev-only-secret:${projectScope}`;
  }

  return '';
};

const getEncryptionKey = () => {
  const secret = getEncryptionSecret();
  if (!secret) return null;
  return createHash('sha256').update(secret).digest();
};

const encryptToken = (plainToken) => {
  const key = getEncryptionKey();
  if (!key) {
    throw createTelegramError('server_config_required', '\u0644\u0627 \u064a\u0645\u0643\u0646 \u062d\u0641\u0638 \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u0627\u0644\u0622\u0646 \u0644\u0623\u0646 \u0625\u0639\u062f\u0627\u062f \u0627\u0644\u062e\u0627\u062f\u0645 \u063a\u064a\u0631 \u0645\u0643\u062a\u0645\u0644.');
  }

  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plainToken), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
};

const decryptToken = (encrypted) => {
  if (!encrypted?.iv || !encrypted?.tag || !encrypted?.ciphertext) return '';

  const key = getEncryptionKey();
  if (!key) {
    throw createTelegramError('server_config_required', '\u062a\u0639\u0630\u0631 \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u0627\u0644\u062d\u0627\u0644\u064a. \u0623\u0643\u0645\u0644 \u0625\u0639\u062f\u0627\u062f \u0627\u0644\u062e\u0627\u062f\u0645 \u0623\u0648 \u0623\u0639\u062f \u0627\u0644\u0631\u0628\u0637 \u0645\u0646 \u0644\u0648\u062d\u0629 \u0627\u0644\u0623\u062f\u0645\u0646.');
  }

  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(encrypted.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
      decipher.final(),
    ]);

    return plaintext.toString('utf8');
  } catch {
    throw createTelegramError('needs_reconnect', '\u062a\u0639\u0630\u0631 \u0642\u0631\u0627\u0621\u0629 \u0628\u064a\u0627\u0646\u0627\u062a \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u0627\u0644\u062d\u0627\u0644\u064a\u0629. \u0623\u0639\u062f \u0627\u0644\u0631\u0628\u0637 \u0645\u0646 \u0644\u0648\u062d\u0629 \u0627\u0644\u0623\u062f\u0645\u0646.');
  }
};

const normalizeNotifications = (notifications) => {
  const source = notifications && typeof notifications === 'object' ? notifications : {};
  return {
    newOrder: Boolean(source.newOrder ?? DEFAULT_NOTIFICATIONS.newOrder),
    orderStatus: Boolean(source.orderStatus ?? DEFAULT_NOTIFICATIONS.orderStatus),
    systemErrors: Boolean(source.systemErrors ?? DEFAULT_NOTIFICATIONS.systemErrors),
    adminActions: Boolean(source.adminActions ?? DEFAULT_NOTIFICATIONS.adminActions),
  };
};

const maskTelegramToken = (token) => {
  const value = String(token || '').trim();
  if (!value) return '';

  const [prefix, suffix] = value.split(':');
  if (!suffix) return `${value.slice(0, 4)}****`;

  const visibleSuffix = suffix.length > 4 ? `${suffix.slice(0, 3)}****${suffix.slice(-1)}` : `${suffix.slice(0, 1)}****`;
  return `${prefix}:${visibleSuffix}`;
};

const maskChatId = (chatId) => {
  const value = String(chatId || '').trim();
  if (!value) return '';
  if (value.length <= 4) return `***${value}`;
  return `${'*'.repeat(Math.max(2, value.length - 4))}${value.slice(-4)}`;
};

const isValidBotToken = (token) => /^\d{6,}:[A-Za-z0-9_-]{20,}$/.test(String(token || '').trim());
const isValidChatId = (chatId) => /^-?\d{5,20}$/.test(String(chatId || '').trim());

const getSettingsRef = (db) => doc(db, TELEGRAM_COLLECTION, TELEGRAM_DOC_ID);

const readTelegramSettingsDocument = async () => {
  const db = getDb();
  if (!db) return null;

  try {
    const snapshot = await getDoc(getSettingsRef(db));
    if (!snapshot.exists()) return null;
    return snapshot.data() || null;
  } catch {
    return null;
  }
};

const writeTelegramSettingsDocument = async (docData) => {
  const db = getDb();
  if (!db) {
    throw createTelegramError('firebase_not_configured', 'Firebase is not configured for Telegram settings.');
  }

  await setDoc(
    getSettingsRef(db),
    {
      ...docData,
      updatedAt: new Date().toISOString(),
    },
    { merge: true },
  );
};

const getConnectionStatus = ({ docData, token, chatId, errorCode }) => {
  const hasStoredToken = Boolean(token || docData?.token?.ciphertext || docData?.legacyToken);
  if (!hasStoredToken || !chatId) return 'disconnected';
  if (errorCode === 'server_config_required') return 'server_config_required';
  if (errorCode === 'needs_reconnect') return 'needs_reconnect';
  return docData?.lastTestOk ? 'connected' : 'not_verified';
};

const buildPublicTelegramSettings = (docData, token, options = {}) => {
  const notifications = normalizeNotifications(docData?.notifications);
  const enabled = Boolean(docData?.enabled);
  const chatId = sanitizeText(docData?.chatId, 40);
  const hasStoredToken = Boolean(token || docData?.token?.ciphertext || docData?.legacyToken);
  const errorCode = sanitizeText(options.errorCode, 80).toLowerCase();
  const publicError = sanitizeText(options.errorMessage, 240) || sanitizeText(docData?.lastError, 240);

  return {
    enabled,
    hasToken: hasStoredToken,
    botTokenMasked: token ? maskTelegramToken(token) : hasStoredToken ? '????????' : '',
    chatId,
    chatIdMasked: chatId ? maskChatId(chatId) : '',
    notifications,
    connectionStatus: getConnectionStatus({ docData, token, chatId, errorCode }),
    requiresReconnect: errorCode === 'needs_reconnect',
    requiresServerConfig: errorCode === 'server_config_required',
    lastTestAt: docData?.lastTestAt || '',
    lastError: publicError,
  };
};

const resolveStoredTelegramSettings = async () => {
  const docData = await readTelegramSettingsDocument();
  if (!docData) {
    return { docData: null, token: '', chatId: '', errorCode: '', errorMessage: '' };
  }

  const chatId = sanitizeText(docData.chatId, 40);

  try {
    let token = '';
    if (docData.token?.ciphertext) {
      token = decryptToken(docData.token);
    } else if (docData.legacyToken) {
      token = String(docData.legacyToken || '').trim();
    }

    return { docData, token, chatId, errorCode: '', errorMessage: '' };
  } catch (error) {
    return {
      docData,
      token: '',
      chatId,
      errorCode: getTelegramErrorCode(error),
      errorMessage: sanitizeText(error?.message, 240),
    };
  }
};

const getTelegramSettingsForAdmin = async () => {
  const resolved = await resolveStoredTelegramSettings();
  if (!resolved.docData) {
    return buildPublicTelegramSettings(null, '');
  }

  return buildPublicTelegramSettings(resolved.docData, resolved.token, {
    errorCode: resolved.errorCode,
    errorMessage: resolved.errorMessage,
  });
};

const saveTelegramSettings = async (payload) => {
  const input = payload && typeof payload === 'object' ? payload : {};
  const { docData: existingDoc, token: existingToken, errorCode } = await resolveStoredTelegramSettings();

  const botTokenInput = sanitizeText(input.botToken, 240);
  const chatIdInput = sanitizeText(input.chatId, 40);
  const tokenToUse = botTokenInput || (errorCode ? '' : existingToken);
  const chatIdToUse = chatIdInput || sanitizeText(existingDoc?.chatId, 40);

  if (!tokenToUse || !isValidBotToken(tokenToUse)) {
    throw createTelegramError('invalid_bot_token', '\u0631\u0645\u0632 Bot Token \u063a\u064a\u0631 \u0635\u0627\u0644\u062d.');
  }

  if (!chatIdToUse || !isValidChatId(chatIdToUse)) {
    throw createTelegramError('invalid_chat_id', '\u0642\u064a\u0645\u0629 Chat ID \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629.');
  }

  const nextDoc = {
    enabled: Boolean(input.enabled),
    chatId: chatIdToUse,
    token: encryptToken(tokenToUse),
    notifications: normalizeNotifications(input.notifications || existingDoc?.notifications),
    lastError: '',
    lastTestAt: existingDoc?.lastTestAt || '',
    lastTestOk: false,
  };

  await writeTelegramSettingsDocument(nextDoc);
  return buildPublicTelegramSettings(nextDoc, tokenToUse);
};

const disconnectTelegramSettings = async () => {
  const { docData } = await resolveStoredTelegramSettings();
  const nextDoc = {
    enabled: false,
    chatId: '',
    token: null,
    legacyToken: '',
    notifications: normalizeNotifications(docData?.notifications),
    lastTestAt: '',
    lastTestOk: false,
    lastError: '',
  };

  await writeTelegramSettingsDocument(nextDoc);
  return buildPublicTelegramSettings(nextDoc, '');
};

const formatMoney = (value) => {
  const amount = Number(value);
  if (!Number.isFinite(amount)) return '-';
  return `${new Intl.NumberFormat('fr-DZ').format(amount)} \u062f.\u062c`;
};

const formatDateTime = (value = new Date()) => {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return sanitizeText(value, 80) || '-';
  return date.toLocaleString('ar-DZ');
};

const toStatusLabel = (status) => {
  const normalized = sanitizeText(status, 40).toLowerCase();
  switch (normalized) {
    case 'pending':
      return '\u0642\u064a\u062f \u0627\u0644\u0645\u0631\u0627\u062c\u0639\u0629';
    case 'confirmed':
      return '\u062a\u0645 \u0627\u0644\u062a\u0623\u0643\u064a\u062f';
    case 'processing':
      return '\u0642\u064a\u062f \u0627\u0644\u062a\u062d\u0636\u064a\u0631';
    case 'shipped':
      return '\u062a\u0645 \u0627\u0644\u0634\u062d\u0646';
    case 'out_for_delivery':
      return '\u062e\u0631\u062c \u0644\u0644\u062a\u0648\u0635\u064a\u0644';
    case 'delivered':
      return '\u062a\u0645 \u0627\u0644\u062a\u0633\u0644\u064a\u0645';
    case 'cancelled':
      return '\u0645\u0644\u063a\u064a';
    default:
      return sanitizeText(status, 60) || '\u063a\u064a\u0631 \u0645\u062d\u062f\u062f\u0629';
  }
};

const formatItemsList = (items = []) => {
  if (!Array.isArray(items) || items.length === 0) {
    return '\u2022 \u0644\u0627 \u062a\u0648\u062c\u062f \u0645\u0646\u062a\u062c\u0627\u062a \u0645\u0631\u0641\u0642\u0629';
  }

  return items
    .slice(0, 8)
    .map((item) => {
      const qty = Number(item?.qty) || 0;
      const name = escapeHtml(sanitizeText(item?.name, 90) || '\u0645\u0646\u062a\u062c');
      const size = sanitizeText(item?.selectedSize, 30);
      const color = sanitizeText(item?.selectedColor, 30);
      const extras = [size ? `\u0627\u0644\u0645\u0642\u0627\u0633: ${escapeHtml(size)}` : '', color ? `\u0627\u0644\u0644\u0648\u0646: ${escapeHtml(color)}` : '']
        .filter(Boolean)
        .join(' | ');
      const linePrice = Number.isFinite(Number(item?.lineTotal)) ? formatMoney(item.lineTotal) : formatMoney((Number(item?.price) || 0) * qty);
      return [`\u2022 ${name} ? ${qty || 1}`, extras ? `  ${extras}` : '', `  ${linePrice}`].filter(Boolean).join('\n');
    })
    .join('\n');
};

const formatTelegramEventMessage = ({ eventType, payload = {}, message = '' }) => {
  const safePayload = payload && typeof payload === 'object' ? payload : {};
  const fallback = sanitizeText(message, 2600);

  if (eventType === 'new_order') {
    return [
      '<b>\u{1F6D2} \u0637\u0644\u0628 \u062c\u062f\u064a\u062f \u0641\u064a \u0627\u0644\u0645\u062a\u062c\u0631</b>',
      '',
      `<b>\u{1F464} \u0627\u0644\u0632\u0628\u0648\u0646:</b> ${escapeHtml(sanitizeText(safePayload.customer?.name || safePayload.customerName, 120) || '-')}`,
      `<b>\u{1F4DE} \u0627\u0644\u0647\u0627\u062a\u0641:</b> ${escapeHtml(sanitizeText(safePayload.customer?.phone || safePayload.phone, 60) || '-')}`,
      `<b>\u{1F4CD} \u0627\u0644\u0648\u0644\u0627\u064a\u0629:</b> ${escapeHtml(sanitizeText(safePayload.customer?.wilaya || safePayload.wilaya, 80) || '-')}`,
      `<b>\u{1F3D8} \u0627\u0644\u0628\u0644\u062f\u064a\u0629:</b> ${escapeHtml(sanitizeText(safePayload.customer?.commune || safePayload.commune, 80) || '-')}`,
      `<b>\u{1F4B3} \u0627\u0644\u0645\u062c\u0645\u0648\u0639:</b> ${formatMoney(safePayload.totalPrice)}`,
      Number(safePayload.discount) > 0 ? `<b>\u{1F3F7} \u0627\u0644\u062e\u0635\u0645:</b> ${formatMoney(safePayload.discount)}` : '',
      safePayload.couponCode ? `<b>\u{1F39F} \u0627\u0644\u0643\u0648\u0628\u0648\u0646:</b> ${escapeHtml(sanitizeText(safePayload.couponCode, 40))}` : '',
      `<b>\u{1F552} \u0627\u0644\u0648\u0642\u062a:</b> ${formatDateTime()}`,
      '',
      '<b>\u{1F4E6} \u0627\u0644\u0645\u0646\u062a\u062c\u0627\u062a</b>',
      formatItemsList(safePayload.items),
    ]
      .filter(Boolean)
      .join('\n');
  }

  if (eventType === 'order_status_changed') {
    return [
      '<b>\u{1F69A} \u062a\u062d\u062f\u064a\u062b \u062d\u0627\u0644\u0629 \u0637\u0644\u0628</b>',
      '',
      `<b>\u{1F9FE} \u0631\u0642\u0645 \u0627\u0644\u0637\u0644\u0628:</b> #${escapeHtml(sanitizeText(safePayload.orderId, 40) || '-')}`,
      `<b>\u{1F501} \u0627\u0644\u062d\u0627\u0644\u0629 \u0627\u0644\u0633\u0627\u0628\u0642\u0629:</b> ${escapeHtml(toStatusLabel(safePayload.previousStatus))}`,
      `<b>\u2705 \u0627\u0644\u062d\u0627\u0644\u0629 \u0627\u0644\u062c\u062f\u064a\u062f\u0629:</b> ${escapeHtml(toStatusLabel(safePayload.nextStatus))}`,
      safePayload.customerName ? `<b>\u{1F464} \u0627\u0644\u0632\u0628\u0648\u0646:</b> ${escapeHtml(sanitizeText(safePayload.customerName, 120))}` : '',
      `<b>\u{1F468}\u200D\u{1F4BC} \u0628\u0648\u0627\u0633\u0637\u0629:</b> ${escapeHtml(sanitizeText(safePayload.adminEmail, 120) || 'admin')}`,
      `<b>\u{1F552} \u0627\u0644\u0648\u0642\u062a:</b> ${formatDateTime()}`,
    ]
      .filter(Boolean)
      .join('\n');
  }

  if (eventType === 'system_error') {
    return [
      '<b>\u{1F6A8} \u062a\u0646\u0628\u064a\u0647 \u0646\u0638\u0627\u0645</b>',
      '',
      `<b>\u{1F9E9} \u0627\u0644\u0648\u062d\u062f\u0629:</b> ${escapeHtml(sanitizeText(safePayload.module, 80) || 'system')}`,
      `<b>\u26A0\uFE0F \u0627\u0644\u0645\u0633\u062a\u0648\u0649:</b> ${escapeHtml(sanitizeText(safePayload.severity, 40) || '\u0645\u0631\u062a\u0641\u0639')}`,
      `<b>\u{1F4DD} \u0627\u0644\u0645\u0644\u062e\u0635:</b> ${escapeHtml(sanitizeText(safePayload.message || fallback, 240) || '\u062a\u0645 \u062a\u0633\u062c\u064a\u0644 \u062e\u0637\u0623 \u064a\u062d\u062a\u0627\u062c \u0645\u0631\u0627\u062c\u0639\u0629.')}`,
      safePayload.suggestedAction ? `<b>\u{1F6E0} \u0627\u0644\u0625\u062c\u0631\u0627\u0621 \u0627\u0644\u0645\u0642\u062a\u0631\u062d:</b> ${escapeHtml(sanitizeText(safePayload.suggestedAction, 160))}` : '',
      `<b>\u{1F468}\u200D\u{1F4BC} \u0628\u0648\u0627\u0633\u0637\u0629:</b> ${escapeHtml(sanitizeText(safePayload.adminEmail, 120) || 'system')}`,
      `<b>\u{1F552} \u0627\u0644\u0648\u0642\u062a:</b> ${formatDateTime()}`,
    ]
      .filter(Boolean)
      .join('\n');
  }

  if (eventType === 'telegram_test') {
    return [
      '<b>\u2705 \u0627\u062e\u062a\u0628\u0627\u0631 \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645</b>',
      '',
      '\u062a\u0645 \u0625\u0631\u0633\u0627\u0644 \u0647\u0630\u0647 \u0627\u0644\u0631\u0633\u0627\u0644\u0629 \u0644\u0644\u062a\u0623\u0643\u062f \u0645\u0646 \u0623\u0646 \u0627\u0644\u0631\u0628\u0637 \u064a\u0639\u0645\u0644 \u0628\u0634\u0643\u0644 \u0635\u062d\u064a\u062d.',
      `<b>\u{1F4AC} Chat ID:</b> ${escapeHtml(sanitizeText(safePayload.chatId, 40) || '-')}`,
      `<b>\u{1F552} \u0627\u0644\u0648\u0642\u062a:</b> ${formatDateTime()}`,
    ].join('\n');
  }

  return [
    '<b>\u{1F6E0} \u0625\u0634\u0639\u0627\u0631 \u0625\u062f\u0627\u0631\u064a</b>',
    '',
    `<b>\u{1F4CC} \u0627\u0644\u0625\u062c\u0631\u0627\u0621:</b> ${escapeHtml(sanitizeText(safePayload.action, 100) || sanitizeText(eventType, 80) || 'admin_action')}`,
    safePayload.entity ? `<b>\u{1F4C1} \u0627\u0644\u0642\u0633\u0645:</b> ${escapeHtml(sanitizeText(safePayload.entity, 100))}` : '',
    safePayload.entityId ? `<b>\u{1F194} \u0627\u0644\u0645\u0639\u0631\u0641:</b> ${escapeHtml(sanitizeText(safePayload.entityId, 80))}` : '',
    safePayload.label ? `<b>\u{1F4DD} \u0627\u0644\u062a\u0641\u0627\u0635\u064a\u0644:</b> ${escapeHtml(sanitizeText(safePayload.label, 180))}` : '',
    `<b>\u{1F468}\u200D\u{1F4BC} \u0628\u0648\u0627\u0633\u0637\u0629:</b> ${escapeHtml(sanitizeText(safePayload.adminEmail, 120) || 'admin')}`,
    `<b>\u{1F552} \u0627\u0644\u0648\u0642\u062a:</b> ${formatDateTime()}`,
  ]
    .filter(Boolean)
    .join('\n');
};

const sendTelegramMessage = async ({ botToken, chatId, text }) => {
  const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: 'HTML',
      disable_web_page_preview: true,
    }),
  });

  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload?.ok) {
    return {
      ok: false,
      error: sanitizeText(payload?.description || `Telegram API HTTP ${response.status}`, 200),
    };
  }

  return { ok: true };
};

const saveTelegramTestStatus = async ({ ok, error }) => {
  const patch = {
    lastTestAt: new Date().toISOString(),
    lastTestOk: Boolean(ok),
    lastError: ok ? '' : sanitizeText(error, 240),
  };
  await writeTelegramSettingsDocument(patch);
};

const testTelegramSettings = async (payload = {}) => {
  const { docData: existingDoc, token: storedToken, chatId: storedChatId, errorCode } = await resolveStoredTelegramSettings();
  const providedToken = sanitizeText(payload.botToken, 240);
  const botToken = providedToken || (errorCode ? '' : storedToken);
  const chatId = sanitizeText(payload.chatId, 40) || storedChatId;

  if (!botToken || !isValidBotToken(botToken)) {
    throw createTelegramError('invalid_bot_token', '\u0631\u0645\u0632 Bot Token \u063a\u064a\u0631 \u0635\u0627\u0644\u062d \u0644\u0627\u062e\u062a\u0628\u0627\u0631 \u0627\u0644\u0631\u0628\u0637.');
  }
  if (!chatId || !isValidChatId(chatId)) {
    throw createTelegramError('invalid_chat_id', '\u0642\u064a\u0645\u0629 Chat ID \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629 \u0644\u0627\u062e\u062a\u0628\u0627\u0631 \u0627\u0644\u0631\u0628\u0637.');
  }

  const testMessage = formatTelegramEventMessage({
    eventType: 'telegram_test',
    payload: { chatId },
  });

  const sendResult = await sendTelegramMessage({
    botToken,
    chatId,
    text: testMessage,
  });

  if (!sendResult.ok) {
    await saveTelegramTestStatus({ ok: false, error: '\u0641\u0634\u0644 \u0625\u0631\u0633\u0627\u0644 \u0631\u0633\u0627\u0644\u0629 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631. \u062a\u062d\u0642\u0642 \u0645\u0646 Bot Token \u0648Chat ID.' });
    throw createTelegramError('test_failed', '\u0641\u0634\u0644 \u0625\u0631\u0633\u0627\u0644 \u0631\u0633\u0627\u0644\u0629 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631. \u062a\u062d\u0642\u0642 \u0645\u0646 Bot Token \u0648Chat ID \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.');
  }

  const patch = {
    ...(existingDoc || {}),
    enabled: Boolean(payload.enabled ?? existingDoc?.enabled ?? true),
    chatId,
    notifications: normalizeNotifications(payload.notifications || existingDoc?.notifications),
    lastTestAt: new Date().toISOString(),
    lastTestOk: true,
    lastError: '',
  };

  if (providedToken || !existingDoc?.token?.ciphertext) {
    patch.token = encryptToken(botToken);
  }

  await writeTelegramSettingsDocument(patch);
  return buildPublicTelegramSettings(patch, botToken);
};

const mapEventToFlag = (eventType) => {
  switch (eventType) {
    case 'new_order':
      return 'newOrder';
    case 'order_status_changed':
      return 'orderStatus';
    case 'system_error':
      return 'systemErrors';
    default:
      return 'adminActions';
  }
};

const resolveTelegramRuntimeConfig = async () => {
  const { docData, token, chatId, errorCode, errorMessage } = await resolveStoredTelegramSettings();

  if (errorCode === 'server_config_required' || errorCode === 'needs_reconnect') {
    return {
      ok: false,
      error: errorMessage || '\u062a\u0639\u0630\u0631 \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u0627\u0644\u062d\u0627\u0644\u064a. \u0623\u0639\u062f \u0627\u0644\u0631\u0628\u0637 \u0645\u0646 \u0644\u0648\u062d\u0629 \u0627\u0644\u0623\u062f\u0645\u0646.',
      code: errorCode,
    };
  }

  if (token && chatId) {
    return {
      ok: true,
      token,
      chatId,
      enabled: Boolean(docData?.enabled),
      source: 'dynamic',
    };
  }

  return {
    ok: false,
    error: '\u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u063a\u064a\u0631 \u0645\u0641\u0639\u0651\u0644 \u062d\u0627\u0644\u064a\u064b\u0627. \u0627\u062d\u0641\u0638 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0631\u0628\u0637 \u0645\u0646 \u0644\u0648\u062d\u0629 \u0627\u0644\u0623\u062f\u0645\u0646 \u0623\u0648\u0644\u064b\u0627.',
    code: 'disconnected',
  };
};

const sendTelegramEventNotification = async ({ eventType, message = '', payload = {} }) => {
  try {
    const { docData, token, chatId, errorCode, errorMessage } = await resolveStoredTelegramSettings();

    if (errorCode === 'server_config_required' || errorCode === 'needs_reconnect') {
      return { ok: false, delivered: false, error: errorMessage };
    }

    if (!docData || !docData.enabled || !token || !chatId) {
      return { ok: true, delivered: false, reason: 'integration-disabled' };
    }

    const notifications = normalizeNotifications(docData.notifications);
    const eventFlag = mapEventToFlag(eventType);
    if (!notifications[eventFlag]) {
      return { ok: true, delivered: false, reason: 'notification-disabled' };
    }

    const finalMessage = sanitizeText(message, 2600)
      ? message
      : formatTelegramEventMessage({ eventType, payload });

    const sendResult = await sendTelegramMessage({
      botToken: token,
      chatId,
      text: finalMessage,
    });

    if (!sendResult.ok) {
      return { ok: false, delivered: false, error: sendResult.error };
    }
    return { ok: true, delivered: true };
  } catch (error) {
    return {
      ok: false,
      delivered: false,
      error: sanitizeText(error?.message || '\u062a\u0639\u0630\u0631 \u0625\u0631\u0633\u0627\u0644 \u0625\u0634\u0639\u0627\u0631 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.', 220),
    };
  }
};

const sendTelegramDirectMessage = async ({ text, chatId = '', bypassEnabled = false }) => {
  try {
    const runtime = await resolveTelegramRuntimeConfig();
    if (!runtime.ok) {
      return { ok: false, delivered: false, error: runtime.error || '\u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u063a\u064a\u0631 \u0645\u062a\u0627\u062d \u062d\u0627\u0644\u064a\u064b\u0627.' };
    }

    if (!bypassEnabled && !runtime.enabled) {
      return { ok: true, delivered: false, reason: 'integration-disabled' };
    }

    const targetChatId = sanitizeText(chatId, 40) || runtime.chatId;
    if (!targetChatId) {
      return { ok: false, delivered: false, error: '\u0642\u064a\u0645\u0629 Chat ID \u063a\u064a\u0631 \u0645\u062a\u0648\u0641\u0631\u0629.' };
    }

    const sendResult = await sendTelegramMessage({
      botToken: runtime.token,
      chatId: targetChatId,
      text,
    });

    if (!sendResult.ok) {
      return { ok: false, delivered: false, error: sendResult.error || 'Telegram API failed.' };
    }

    return { ok: true, delivered: true };
  } catch (error) {
    return {
      ok: false,
      delivered: false,
      error: sanitizeText(error?.message || '\u062a\u0639\u0630\u0631 \u0625\u0631\u0633\u0627\u0644 \u0631\u0633\u0627\u0644\u0629 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u0645\u0628\u0627\u0634\u0631\u0629.', 220),
    };
  }
};

export {
  DEFAULT_NOTIFICATIONS,
  disconnectTelegramSettings,
  formatTelegramEventMessage,
  getClientIp,
  getTelegramSettingsForAdmin,
  isRateLimited,
  parseRequestBody,
  resolveTelegramRuntimeConfig,
  sanitizeText,
  saveTelegramSettings,
  sendTelegramDirectMessage,
  sendTelegramEventNotification,
  testTelegramSettings,
  verifyAdminRequest,
};

