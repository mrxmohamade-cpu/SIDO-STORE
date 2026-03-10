import { getClientIp, isRateLimited, parseRequestBody, sanitizeText } from './_telegram.js';
import { resolveTelegramRuntimeConfig, sendTelegramDirectMessage } from './_telegram.js';
import {
  blockIpAddress,
  getSecurityOverview,
  getSecuritySettings,
  listSecurityAlerts,
  listSecurityEvents,
  logAdminAudit,
  logSecurityEvent,
  saveSecuritySettings,
  setAlertState,
  unblockIpAddress,
} from './_security.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 80;

const TELEGRAM_ACTION_CONFIRMATIONS = globalThis.__telegramActionConfirmationsV2 || new Map();
globalThis.__telegramActionConfirmationsV2 = TELEGRAM_ACTION_CONFIRMATIONS;

const DANGEROUS_COMMANDS = new Set(['block_ip', 'unblock_ip', 'disable_reset_password', 'enable_reset_password']);

const parseCommand = (text) => {
  const normalized = String(text || '').trim();
  if (!normalized.startsWith('/')) return null;
  const [commandWithPrefix, ...rest] = normalized.split(/\s+/);
  return { command: commandWithPrefix.replace(/^\//, '').toLowerCase(), args: rest, raw: normalized };
};

const normalizeTelegramActor = ({ chatId, userId, username }) => ({
  email: `telegram:${userId || 'unknown'}`,
  uid: `tg:${userId || 'unknown'}`,
  ipAddress: `telegram:${chatId || 'unknown'}`,
  username: sanitizeText(username, 80),
});

const formatRiskLevel = (value) => {
  switch (String(value || '').toLowerCase()) {
    case 'critical': return 'Critique';
    case 'high': return 'Eleve';
    case 'medium': return 'Moyen';
    case 'low': return 'Faible';
    default: return sanitizeText(value, 20) || 'Non defini';
  }
};

const buildHelpMessage = () => [
  '<b>[HELP]</b> Commandes du centre de securite',
  '',
  '/status - Etat general du systeme',
  '/security - Resume securite rapide',
  '/alerts - Dernieres alertes non resolues',
  '/failed_logins - Derniers echecs de connexion admin',
  '/reset_requests - Dernieres demandes de reinitialisation',
  '/block_ip <ip> - Bloquer une adresse IP (confirmation requise)',
  '/unblock_ip <ip> - Debloquer une adresse IP (confirmation requise)',
  '/disable_reset_password - Desactiver la reinitialisation du mot de passe',
  '/enable_reset_password - Reactiver la reinitialisation du mot de passe',
  '/mute <event_type> - Couper un type d alerte',
  '/unmute <event_type> - Reactiver un type d alerte',
  '/ack <alert_id> - Marquer une alerte comme lue',
  '/resolve <alert_id> - Marquer une alerte comme resolue',
  '/help - Afficher cette aide',
].join('\n');

const sendReply = async ({ chatId, text }) => sendTelegramDirectMessage({ chatId, text, bypassEnabled: true });

const formatAlertsMessage = (alerts = []) => {
  if (alerts.length === 0) return '<b>[ALERTES]</b> Aucune alerte active\n\nAucune alerte non resolue pour le moment.';
  return [
    '<b>[ALERTES]</b> Dernieres alertes',
    '',
    ...alerts.slice(0, 8).map((alert) => `- <b>${sanitizeText(alert.id, 16)}</b> | ${formatRiskLevel(alert.severity)} | ${sanitizeText(alert.eventType, 42)}\n${sanitizeText(alert.summary, 110)}`),
  ].join('\n');
};

const formatEventsMessage = (title, events = []) => {
  if (events.length === 0) return `<b>${title}</b>\n\nAucune donnee correspondante.`;
  return [
    `<b>${title}</b>`,
    '',
    ...events.slice(0, 8).map((event) => `- ${sanitizeText(event.createdAt, 24)} | ${sanitizeText(event.ipAddress, 40)} | ${sanitizeText(event.summary, 90)}`),
  ].join('\n');
};

const createConfirmationCode = () => String(Math.floor(100000 + Math.random() * 900000));

const registerPendingConfirmation = ({ userId, action, payload }) => {
  const code = createConfirmationCode();
  TELEGRAM_ACTION_CONFIRMATIONS.set(code, { userId: String(userId || ''), action, payload, expiresAt: Date.now() + 2 * 60 * 1000 });
  return code;
};

const consumePendingConfirmation = ({ userId, code }) => {
  const item = TELEGRAM_ACTION_CONFIRMATIONS.get(code);
  if (!item) return null;
  if (item.userId !== String(userId || '')) return null;
  if (Date.now() > Number(item.expiresAt || 0)) {
    TELEGRAM_ACTION_CONFIRMATIONS.delete(code);
    return null;
  }
  TELEGRAM_ACTION_CONFIRMATIONS.delete(code);
  return item;
};

const executeCommandAction = async ({ command, args, actor }) => {
  if (command === 'block_ip') {
    const ipAddress = sanitizeText(args[0], 90);
    if (!ipAddress) throw new Error('Syntaxe correcte: /block_ip <ip>');
    await blockIpAddress({ ipAddress, reason: 'Blocked from Telegram command', actor });
    return `Adresse IP bloquee: ${ipAddress}`;
  }
  if (command === 'unblock_ip') {
    const ipAddress = sanitizeText(args[0], 90);
    if (!ipAddress) throw new Error('Syntaxe correcte: /unblock_ip <ip>');
    await unblockIpAddress({ ipAddress, actor });
    return `Adresse IP debloquee: ${ipAddress}`;
  }
  if (command === 'disable_reset_password' || command === 'enable_reset_password') {
    const current = await getSecuritySettings();
    const enabled = command === 'enable_reset_password';
    await saveSecuritySettings({ controls: { ...current.controls, resetPasswordEnabled: enabled } }, actor);
    return enabled ? 'La reinitialisation du mot de passe est reactivee.' : 'La reinitialisation du mot de passe est desactivee temporairement.';
  }
  return 'Commande non prise en charge pour le moment.';
};

const canUseCommandChannel = (settings, chatId, userId) => {
  if (!settings.telegram.allowCommands) return false;
  const allowedUsers = Array.isArray(settings.telegram.allowedTelegramUserIds) ? settings.telegram.allowedTelegramUserIds : [];
  const allowedChats = Array.isArray(settings.telegram.allowedChatIds) ? settings.telegram.allowedChatIds : [];
  if (allowedUsers.length > 0 && !allowedUsers.includes(String(userId))) return false;
  if (allowedChats.length > 0 && !allowedChats.includes(String(chatId))) return false;
  return true;
};

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Methode non autorisee.' });

  const clientIp = getClientIp(req);
  if (isRateLimited('telegram-webhook', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: 'Trop de requetes.' });
  }

  const secretExpected = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
  if (secretExpected) {
    const secretReceived = String(req.headers['x-telegram-bot-api-secret-token'] || '').trim();
    if (!secretReceived || secretReceived !== secretExpected) {
      return res.status(403).json({ error: 'Acces refuse.' });
    }
  }

  const runtime = await resolveTelegramRuntimeConfig();
  if (!runtime.ok) return res.status(503).json({ error: 'Telegram indisponible.' });

  const body = parseRequestBody(req.body);
  if (!body || typeof body !== 'object') return res.status(200).json({ ok: true });

  const update = body.message || body.edited_message || body.channel_post;
  const messageText = sanitizeText(update?.text, 2600);
  const commandInfo = parseCommand(messageText);
  if (!commandInfo) return res.status(200).json({ ok: true });

  const chatId = String(update?.chat?.id || '').trim();
  const userId = String(update?.from?.id || '').trim();
  const username = sanitizeText(update?.from?.username || update?.from?.first_name || '', 120);
  const settings = await getSecuritySettings();
  const actor = normalizeTelegramActor({ chatId, userId, username });
  const commandRate = Number(settings.telegram.commandRateLimitPerMinute) || 20;
  const commandRateScope = `telegram-command:${chatId || 'unknown'}`;

  if (isRateLimited(commandRateScope, clientIp, commandRate, RATE_LIMIT_WINDOW_MS)) {
    await sendReply({ chatId, text: 'Trop de commandes en peu de temps. Reessayez dans un instant.' });
    return res.status(200).json({ ok: true });
  }

  if (!canUseCommandChannel(settings, chatId, userId)) {
    await logSecurityEvent({
      eventType: 'telegram_command_denied',
      severity: 'high',
      source: 'telegram_webhook',
      summary: 'Unauthorized Telegram command attempt.',
      ipAddress: clientIp,
      metadata: { command: commandInfo.command, chatId, userId },
    });
    await sendReply({ chatId, text: 'Acces refuse a cette commande Telegram.' });
    return res.status(200).json({ ok: true });
  }

  await logAdminAudit({
    action: `telegram_command_${commandInfo.command}`,
    actorEmail: actor.email,
    actorUid: actor.uid,
    ipAddress: actor.ipAddress,
    targetType: 'telegram_command',
    targetId: commandInfo.command,
    metadata: { args: commandInfo.args, username, chatId, userId },
  });

  await logSecurityEvent({
    eventType: 'telegram_command',
    severity: 'medium',
    source: 'telegram_webhook',
    summary: `Telegram command executed: ${commandInfo.command}`,
    ipAddress: clientIp,
    userEmail: actor.email,
    metadata: { command: commandInfo.command, chatId, userId, username },
  });

  try {
    if (commandInfo.command === 'help') {
      await sendReply({ chatId, text: buildHelpMessage() });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'confirm') {
      const code = sanitizeText(commandInfo.args[0], 12);
      if (!code) {
        await sendReply({ chatId, text: 'Syntaxe correcte: /confirm <code>' });
        return res.status(200).json({ ok: true });
      }
      const pending = consumePendingConfirmation({ userId, code });
      if (!pending) {
        await sendReply({ chatId, text: 'Code de confirmation invalide ou expire.' });
        return res.status(200).json({ ok: true });
      }
      const resultMessage = await executeCommandAction({ command: pending.action, args: pending.payload.args, actor });
      await sendReply({ chatId, text: `<b>[OK]</b> Action executee\n\n${sanitizeText(resultMessage, 220)}` });
      return res.status(200).json({ ok: true });
    }

    if (DANGEROUS_COMMANDS.has(commandInfo.command)) {
      const code = registerPendingConfirmation({ userId, action: commandInfo.command, payload: { args: commandInfo.args } });
      await sendReply({ chatId, text: [
        '<b>[CONFIRMATION]</b> Confirmation requise',
        '',
        `Commande: /${commandInfo.command}`,
        `Code: <b>${code}</b>`,
        'Envoyez /confirm <code> sous 2 minutes pour valider.',
      ].join('\n') });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'status' || commandInfo.command === 'security') {
      const overview = await getSecurityOverview();
      const metrics = overview.metrics || {};
      const message = [
        '<b>[SECURITE]</b> Tableau securite',
        '',
        `<b>Niveau de risque:</b> ${formatRiskLevel(metrics.riskLevel)}`,
        `<b>Alertes aujourd hui:</b> ${Number(metrics.alertsToday) || 0}`,
        `<b>Echecs de connexion:</b> ${Number(metrics.failedLoginsToday) || 0}`,
        `<b>Demandes reset:</b> ${Number(metrics.resetRequestsToday) || 0}`,
        `<b>IPs bloquees:</b> ${Number(metrics.blockedIpsCount) || 0}`,
        `<b>Alertes non resolues:</b> ${Number(metrics.unresolvedAlerts) || 0}`,
      ].join('\n');
      await sendReply({ chatId, text: message });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'alerts') {
      const alerts = await listSecurityAlerts({ status: 'unresolved' });
      await sendReply({ chatId, text: formatAlertsMessage(alerts) });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'failed_logins') {
      const events = await listSecurityEvents({ eventType: 'admin_login_failed' });
      await sendReply({ chatId, text: formatEventsMessage('[AUTH] Derniers echecs de connexion admin', events) });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'reset_requests') {
      const events = await listSecurityEvents({ eventType: 'forgot_password_requested' });
      await sendReply({ chatId, text: formatEventsMessage('[RESET] Dernieres demandes de reinitialisation', events) });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'ack' || commandInfo.command === 'resolve') {
      const alertId = sanitizeText(commandInfo.args[0], 80);
      if (!alertId) {
        await sendReply({ chatId, text: `Syntaxe correcte: /${commandInfo.command} <alert_id>` });
        return res.status(200).json({ ok: true });
      }
      if (commandInfo.command === 'ack') {
        await setAlertState({ alertId, patch: { read: true }, actor });
        await sendReply({ chatId, text: `Alerte ${alertId} marquee comme lue.` });
      } else {
        await setAlertState({ alertId, patch: { read: true, status: 'resolved' }, actor });
        await sendReply({ chatId, text: `Alerte ${alertId} marquee comme resolue.` });
      }
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'mute' || commandInfo.command === 'unmute') {
      const eventType = sanitizeText(commandInfo.args[0], 80).toLowerCase();
      if (!eventType) {
        await sendReply({ chatId, text: `Syntaxe correcte: /${commandInfo.command} <event_type>` });
        return res.status(200).json({ ok: true });
      }
      const current = await getSecuritySettings();
      const currentMuted = new Set(Array.isArray(current.telegram.mutedEventTypes) ? current.telegram.mutedEventTypes : []);
      if (commandInfo.command === 'mute') currentMuted.add(eventType);
      if (commandInfo.command === 'unmute') currentMuted.delete(eventType);
      await saveSecuritySettings({ telegram: { ...current.telegram, mutedEventTypes: Array.from(currentMuted) } }, actor);
      await sendReply({ chatId, text: commandInfo.command === 'mute' ? `Alertes coupees pour: ${eventType}` : `Alertes reactivees pour: ${eventType}` });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'user_sessions' || commandInfo.command === 'force_logout') {
      await sendReply({ chatId, text: 'Cette commande est planifiee pour une prochaine phase.' });
      return res.status(200).json({ ok: true });
    }

    await sendReply({ chatId, text: 'Commande inconnue. Utilisez /help pour afficher les commandes disponibles.' });
    return res.status(200).json({ ok: true });
  } catch (error) {
    await logSecurityEvent({
      eventType: 'api_error',
      severity: 'high',
      source: 'telegram_webhook',
      summary: 'Telegram command handler failed.',
      ipAddress: clientIp,
      userEmail: actor.email,
      metadata: { command: commandInfo.command, error: sanitizeText(error?.message, 220) },
    });
    await sendReply({ chatId, text: 'Une erreur est survenue pendant l execution de la commande. Reessayez.' });
    return res.status(200).json({ ok: true });
  }
}
