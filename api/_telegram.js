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

const getEncryptionSecret = () => {
  const configured = String(process.env.TELEGRAM_ENCRYPTION_SECRET || '').trim();
  if (configured) return configured;

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
    throw new Error('TELEGRAM_ENCRYPTION_SECRET is required for secure storage.');
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
    throw new Error('TELEGRAM_ENCRYPTION_SECRET is required to decrypt token.');
  }

  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(encrypted.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
    decipher.final(),
  ]);

  return plaintext.toString('utf8');
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
    throw new Error('Firebase is not configured.');
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

const buildPublicTelegramSettings = (docData, token) => {
  const notifications = normalizeNotifications(docData?.notifications);
  const enabled = Boolean(docData?.enabled);
  const hasToken = Boolean(token);
  const chatId = sanitizeText(docData?.chatId, 40);

  return {
    enabled,
    hasToken,
    botTokenMasked: hasToken ? maskTelegramToken(token) : '',
    chatId,
    chatIdMasked: chatId ? maskChatId(chatId) : '',
    notifications,
    connectionStatus: docData?.lastTestOk ? 'connected' : hasToken && chatId ? 'not_verified' : 'disconnected',
    lastTestAt: docData?.lastTestAt || '',
    lastError: sanitizeText(docData?.lastError, 240),
  };
};

const resolveStoredTelegramSettings = async () => {
  const docData = await readTelegramSettingsDocument();
  if (!docData) return { docData: null, token: '', chatId: '' };

  let token = '';
  if (docData.token?.ciphertext) {
    token = decryptToken(docData.token);
  } else if (docData.legacyToken) {
    token = String(docData.legacyToken || '').trim();
  }

  const chatId = sanitizeText(docData.chatId, 40);
  return { docData, token, chatId };
};

const getTelegramSettingsForAdmin = async () => {
  const { docData, token } = await resolveStoredTelegramSettings();
  if (!docData) {
    return buildPublicTelegramSettings(null, '');
  }
  return buildPublicTelegramSettings(docData, token);
};

const saveTelegramSettings = async (payload) => {
  const input = payload && typeof payload === 'object' ? payload : {};
  const { docData: existingDoc, token: existingToken } = await resolveStoredTelegramSettings();

  const botTokenInput = sanitizeText(input.botToken, 240);
  const chatIdInput = sanitizeText(input.chatId, 40);
  const tokenToUse = botTokenInput || existingToken;
  const chatIdToUse = chatIdInput || sanitizeText(existingDoc?.chatId, 40);

  if (!tokenToUse || !isValidBotToken(tokenToUse)) {
    throw new Error('Bot token is invalid.');
  }

  if (!chatIdToUse || !isValidChatId(chatIdToUse)) {
    throw new Error('Chat ID is invalid.');
  }

  const encryptedToken = encryptToken(tokenToUse);
  const nextDoc = {
    enabled: Boolean(input.enabled),
    chatId: chatIdToUse,
    token: encryptedToken,
    notifications: normalizeNotifications(input.notifications || existingDoc?.notifications),
    lastError: '',
  };

  await writeTelegramSettingsDocument(nextDoc);
  return buildPublicTelegramSettings(nextDoc, tokenToUse);
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
  const { docData: existingDoc, token: storedToken, chatId: storedChatId } = await resolveStoredTelegramSettings();
  const botToken = sanitizeText(payload.botToken, 240) || storedToken;
  const chatId = sanitizeText(payload.chatId, 40) || storedChatId;

  if (!botToken || !isValidBotToken(botToken)) {
    throw new Error('Bot token is invalid for test.');
  }
  if (!chatId || !isValidChatId(chatId)) {
    throw new Error('Chat ID is invalid for test.');
  }

  const testMessage = [
    '<b>Telegram Integration Test</b>',
    '',
    'This message confirms that the current integration settings are valid.',
    `<b>Time:</b> ${new Date().toLocaleString('ar-DZ')}`,
  ].join('\n');

  const sendResult = await sendTelegramMessage({
    botToken,
    chatId,
    text: testMessage,
  });

  if (!sendResult.ok) {
    await saveTelegramTestStatus({ ok: false, error: sendResult.error });
    throw new Error('Failed to send test message. Check Bot token and Chat ID.');
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
  if (!existingDoc?.token?.ciphertext || sanitizeText(payload.botToken, 240)) {
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

const sendTelegramEventNotification = async ({ eventType, message }) => {
  try {
    const { docData, token, chatId } = await resolveStoredTelegramSettings();

    if (!docData || !docData.enabled || !token || !chatId) {
      const legacyToken = String(process.env.TELEGRAM_BOT_TOKEN || '').trim();
      const legacyChatId = String(process.env.TELEGRAM_CHAT_ID || '').trim();
      if (!legacyToken || !legacyChatId) {
        return { ok: true, delivered: false, reason: 'integration-disabled' };
      }

      const legacySend = await sendTelegramMessage({
        botToken: legacyToken,
        chatId: legacyChatId,
        text: message,
      });
      return legacySend.ok
        ? { ok: true, delivered: true }
        : { ok: false, delivered: false, error: legacySend.error };
    }

    const notifications = normalizeNotifications(docData.notifications);
    const eventFlag = mapEventToFlag(eventType);
    if (!notifications[eventFlag]) {
      return { ok: true, delivered: false, reason: 'notification-disabled' };
    }

    const sendResult = await sendTelegramMessage({
      botToken: token,
      chatId,
      text: message,
    });

    if (!sendResult.ok) {
      return { ok: false, delivered: false, error: sendResult.error };
    }
    return { ok: true, delivered: true };
  } catch (error) {
    return {
      ok: false,
      delivered: false,
      error: sanitizeText(error?.message || 'Telegram notification failed.', 220),
    };
  }
};

const resolveTelegramRuntimeConfig = async () => {
  const { docData, token, chatId } = await resolveStoredTelegramSettings();
  if (token && chatId) {
    return {
      ok: true,
      token,
      chatId,
      enabled: Boolean(docData?.enabled),
      source: 'dynamic',
    };
  }

  const legacyToken = String(process.env.TELEGRAM_BOT_TOKEN || '').trim();
  const legacyChatId = String(process.env.TELEGRAM_CHAT_ID || '').trim();
  if (!legacyToken || !legacyChatId) {
    return { ok: false, error: 'Telegram integration is not configured.' };
  }

  return {
    ok: true,
    token: legacyToken,
    chatId: legacyChatId,
    enabled: true,
    source: 'legacy',
  };
};

const sendTelegramDirectMessage = async ({ text, chatId = '', bypassEnabled = false }) => {
  try {
    const runtime = await resolveTelegramRuntimeConfig();
    if (!runtime.ok) {
      return { ok: false, delivered: false, error: runtime.error || 'Telegram runtime unavailable.' };
    }

    if (!bypassEnabled && !runtime.enabled) {
      return { ok: true, delivered: false, reason: 'integration-disabled' };
    }

    const targetChatId = sanitizeText(chatId, 40) || runtime.chatId;
    if (!targetChatId) {
      return { ok: false, delivered: false, error: 'Chat ID is missing.' };
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
      error: sanitizeText(error?.message || 'Failed to send Telegram direct message.', 220),
    };
  }
};
export {
  DEFAULT_NOTIFICATIONS,
  getClientIp,
  getTelegramSettingsForAdmin,
  isRateLimited,
  parseRequestBody,
  sanitizeText,
  saveTelegramSettings,
  sendTelegramDirectMessage,
  sendTelegramEventNotification,
  testTelegramSettings,
  resolveTelegramRuntimeConfig,
  verifyAdminRequest,
};



