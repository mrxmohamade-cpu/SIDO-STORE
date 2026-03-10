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

const DANGEROUS_COMMANDS = new Set([
  'block_ip',
  'unblock_ip',
  'disable_reset_password',
  'enable_reset_password',
]);

const parseCommand = (text) => {
  const normalized = String(text || '').trim();
  if (!normalized.startsWith('/')) return null;

  const [commandWithPrefix, ...rest] = normalized.split(/\s+/);
  const command = commandWithPrefix.replace(/^\//, '').toLowerCase();
  return { command, args: rest, raw: normalized };
};

const normalizeTelegramActor = ({ chatId, userId, username }) => ({
  email: `telegram:${userId || 'unknown'}` ,
  uid: `tg:${userId || 'unknown'}` ,
  ipAddress: `telegram:${chatId || 'unknown'}` ,
  username: sanitizeText(username, 80),
});

const formatRiskLevel = (value) => {
  switch (String(value || '').toLowerCase()) {
    case 'critical': return '\u062d\u0631\u062c';
    case 'high': return '\u0645\u0631\u062a\u0641\u0639';
    case 'medium': return '\u0645\u062a\u0648\u0633\u0637';
    case 'low': return '\u0645\u0646\u062e\u0641\u0636';
    default: return sanitizeText(value, 20) || '\u063a\u064a\u0631 \u0645\u062d\u062f\u062f';
  }
};

const buildHelpMessage = () => [
  '<b>\ud83e\udd16 \u0623\u0648\u0627\u0645\u0631 \u0645\u0631\u0643\u0632 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629</b>',
  '',
  '/status - \u0639\u0631\u0636 \u062d\u0627\u0644\u0629 \u0627\u0644\u0646\u0638\u0627\u0645 \u0648\u0645\u0624\u0634\u0631\u0627\u062a \u0627\u0644\u0623\u0645\u0627\u0646',
  '/security - \u0645\u0644\u062e\u0635 \u0623\u0645\u0646\u064a \u0633\u0631\u064a\u0639',
  '/alerts - \u0639\u0631\u0636 \u0622\u062e\u0631 \u0627\u0644\u062a\u0646\u0628\u064a\u0647\u0627\u062a \u063a\u064a\u0631 \u0627\u0644\u0645\u0639\u0627\u0644\u062c\u0629',
  '/failed_logins - \u0622\u062e\u0631 \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u0627\u0644\u062f\u062e\u0648\u0644 \u0627\u0644\u0641\u0627\u0634\u0644\u0629',
  '/reset_requests - \u0622\u062e\u0631 \u0637\u0644\u0628\u0627\u062a \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631',
  '/block_ip <ip> - \u062d\u0638\u0631 \u0639\u0646\u0648\u0627\u0646 IP \u0628\u0639\u062f \u0627\u0644\u062a\u0623\u0643\u064a\u062f',
  '/unblock_ip <ip> - \u0641\u0643 \u062d\u0638\u0631 \u0639\u0646\u0648\u0627\u0646 IP \u0628\u0639\u062f \u0627\u0644\u062a\u0623\u0643\u064a\u062f',
  '/disable_reset_password - \u0625\u064a\u0642\u0627\u0641 \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0645\u0624\u0642\u062a\u064b\u0627',
  '/enable_reset_password - \u0625\u0639\u0627\u062f\u0629 \u062a\u0641\u0639\u064a\u0644 \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631',
  '/mute <event_type> - \u0643\u062a\u0645 \u0646\u0648\u0639 \u062a\u0646\u0628\u064a\u0647',
  '/unmute <event_type> - \u0625\u0644\u063a\u0627\u0621 \u0643\u062a\u0645 \u0646\u0648\u0639 \u062a\u0646\u0628\u064a\u0647',
  '/ack <alert_id> - \u062a\u0639\u0644\u064a\u0645 \u0627\u0644\u062a\u0646\u0628\u064a\u0647 \u0643\u0645\u0642\u0631\u0648\u0621',
  '/resolve <alert_id> - \u062a\u0639\u0644\u064a\u0645 \u0627\u0644\u062a\u0646\u0628\u064a\u0647 \u0643\u0645\u062d\u0644\u0648\u0644',
  '/help - \u0639\u0631\u0636 \u0647\u0630\u0647 \u0627\u0644\u0623\u0648\u0627\u0645\u0631',
].join('\n');

const sendReply = async ({ chatId, text }) => sendTelegramDirectMessage({
  chatId,
  text,
  bypassEnabled: true,
});

const formatAlertsMessage = (alerts = []) => {
  if (alerts.length === 0) {
    return '<b>\ud83d\udd14 \u0644\u0627 \u062a\u0648\u062c\u062f \u062a\u0646\u0628\u064a\u0647\u0627\u062a \u062d\u0627\u0644\u064a\u064b\u0627</b>\n\n\u0644\u0645 \u064a\u062a\u0645 \u062a\u0633\u062c\u064a\u0644 \u0623\u064a \u062a\u0646\u0628\u064a\u0647 \u063a\u064a\u0631 \u0645\u0639\u0627\u0644\u062c \u062d\u062a\u0649 \u0627\u0644\u0622\u0646.';
  }

  return [
    '<b>\ud83d\udd14 \u0622\u062e\u0631 \u0627\u0644\u062a\u0646\u0628\u064a\u0647\u0627\u062a</b>',
    '',
    ...alerts.slice(0, 8).map((alert) => {
      const severity = formatRiskLevel(alert.severity);
      const summary = sanitizeText(alert.summary, 110);
      return `\u2022 <b>${sanitizeText(alert.id, 16)}</b> | ${severity} | ${sanitizeText(alert.eventType, 42)}\n${summary}`;
    }),
  ].join('\n');
};

const formatEventsMessage = (title, events = []) => {
  if (events.length === 0) {
    return `<b>${title}</b>\n\n\u0644\u0627 \u062a\u0648\u062c\u062f \u0628\u064a\u0627\u0646\u0627\u062a \u0645\u0637\u0627\u0628\u0642\u0629.`;
  }

  return [
    `<b>${title}</b>`,
    '',
    ...events.slice(0, 8).map((event) => `\u2022 ${sanitizeText(event.createdAt, 24)} | ${sanitizeText(event.ipAddress, 40)} | ${sanitizeText(event.summary, 90)}`),
  ].join('\n');
};

const createConfirmationCode = () => String(Math.floor(100000 + Math.random() * 900000));

const registerPendingConfirmation = ({ userId, action, payload }) => {
  const code = createConfirmationCode();
  TELEGRAM_ACTION_CONFIRMATIONS.set(code, {
    userId: String(userId || ''),
    action,
    payload,
    expiresAt: Date.now() + 2 * 60 * 1000,
  });
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
    if (!ipAddress) throw new Error('\u0635\u064a\u063a\u0629 \u0627\u0644\u0623\u0645\u0631 \u0627\u0644\u0635\u062d\u064a\u062d\u0629: /block_ip <ip>');
    await blockIpAddress({ ipAddress, reason: 'Blocked from Telegram command', actor });
    return `\u062a\u0645 \u062d\u0638\u0631 \u0639\u0646\u0648\u0627\u0646 IP: ${ipAddress}`;
  }

  if (command === 'unblock_ip') {
    const ipAddress = sanitizeText(args[0], 90);
    if (!ipAddress) throw new Error('\u0635\u064a\u063a\u0629 \u0627\u0644\u0623\u0645\u0631 \u0627\u0644\u0635\u062d\u064a\u062d\u0629: /unblock_ip <ip>');
    await unblockIpAddress({ ipAddress, actor });
    return `\u062a\u0645 \u0641\u0643 \u062d\u0638\u0631 \u0639\u0646\u0648\u0627\u0646 IP: ${ipAddress}`;
  }

  if (command === 'disable_reset_password' || command === 'enable_reset_password') {
    const current = await getSecuritySettings();
    const enabled = command === 'enable_reset_password';
    await saveSecuritySettings({
      controls: {
        ...current.controls,
        resetPasswordEnabled: enabled,
      },
    }, actor);
    return enabled
      ? '\u062a\u0645 \u0625\u0639\u0627\u062f\u0629 \u062a\u0641\u0639\u064a\u0644 \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631.'
      : '\u062a\u0645 \u0625\u064a\u0642\u0627\u0641 \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0645\u0624\u0642\u062a\u064b\u0627.';
  }

  return '\u0647\u0630\u0627 \u0627\u0644\u0623\u0645\u0631 \u063a\u064a\u0631 \u0645\u062f\u0639\u0648\u0645 \u062d\u0627\u0644\u064a\u064b\u0627.';
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
  if (req.method !== 'POST') {
    return res.status(405).json({ error: '\u0627\u0644\u0637\u0631\u064a\u0642\u0629 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627.' });
  }

  const clientIp = getClientIp(req);
  if (isRateLimited('telegram-webhook', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a.' });
  }

  const secretExpected = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
  if (secretExpected) {
    const secretReceived = String(req.headers['x-telegram-bot-api-secret-token'] || '').trim();
    if (!secretReceived || secretReceived !== secretExpected) {
      return res.status(403).json({ error: '\u062a\u0645 \u0631\u0641\u0636 \u0627\u0644\u0637\u0644\u0628.' });
    }
  }

  const runtime = await resolveTelegramRuntimeConfig();
  if (!runtime.ok) {
    return res.status(503).json({ error: '\u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u063a\u064a\u0631 \u0645\u062a\u0627\u062d \u062d\u0627\u0644\u064a\u064b\u0627.' });
  }

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
    await sendReply({ chatId, text: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0644\u0644\u0623\u0648\u0627\u0645\u0631. \u062d\u0627\u0648\u0644 \u0645\u0646 \u062c\u062f\u064a\u062f \u0628\u0639\u062f \u0642\u0644\u064a\u0644.' });
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
    await sendReply({ chatId, text: '\u0647\u0630\u0627 \u0627\u0644\u062d\u0633\u0627\u0628 \u063a\u064a\u0631 \u0645\u0635\u0631\u062d \u0644\u0647 \u0628\u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0623\u0648\u0627\u0645\u0631 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629.' });
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
        await sendReply({ chatId, text: '\u0635\u064a\u063a\u0629 \u0627\u0644\u0623\u0645\u0631 \u0627\u0644\u0635\u062d\u064a\u062d\u0629: /confirm <code>' });
        return res.status(200).json({ ok: true });
      }

      const pending = consumePendingConfirmation({ userId, code });
      if (!pending) {
        await sendReply({ chatId, text: '\u0631\u0645\u0632 \u0627\u0644\u062a\u0623\u0643\u064a\u062f \u063a\u064a\u0631 \u0635\u0627\u0644\u062d \u0623\u0648 \u0627\u0646\u062a\u0647\u062a \u0635\u0644\u0627\u062d\u064a\u062a\u0647.' });
        return res.status(200).json({ ok: true });
      }

      const resultMessage = await executeCommandAction({ command: pending.action, args: pending.payload.args, actor });
      await sendReply({ chatId, text: `<b>\u2705 \u062a\u0645 \u0627\u0644\u062a\u0646\u0641\u064a\u0630</b>\n\n${sanitizeText(resultMessage, 220)}` });
      return res.status(200).json({ ok: true });
    }

    if (DANGEROUS_COMMANDS.has(commandInfo.command)) {
      const code = registerPendingConfirmation({
        userId,
        action: commandInfo.command,
        payload: { args: commandInfo.args },
      });
      await sendReply({
        chatId,
        text: [
          '<b>\u26a0\ufe0f \u062a\u0623\u0643\u064a\u062f \u0645\u0637\u0644\u0648\u0628</b>',
          '',
          `\u0627\u0644\u0623\u0645\u0631: /${commandInfo.command}`,
          `\u0631\u0645\u0632 \u0627\u0644\u062a\u0623\u0643\u064a\u062f: <b>${code}</b>`,
          '\u0623\u0631\u0633\u0644 /confirm <code> \u062e\u0644\u0627\u0644 \u062f\u0642\u064a\u0642\u062a\u064a\u0646 \u0644\u0625\u062a\u0645\u0627\u0645 \u0627\u0644\u062a\u0646\u0641\u064a\u0630.',
        ].join('\n'),
      });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'status' || commandInfo.command === 'security') {
      const overview = await getSecurityOverview();
      const metrics = overview.metrics || {};
      const message = [
        '<b>\ud83d\udee1\ufe0f \u0645\u0644\u062e\u0635 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629 \u0627\u0644\u0623\u0645\u0646\u064a\u0629</b>',
        '',
        `<b>\u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u062e\u0637\u0631:</b> ${formatRiskLevel(metrics.riskLevel)}`,
        `<b>\u062a\u0646\u0628\u064a\u0647\u0627\u062a \u0627\u0644\u064a\u0648\u0645:</b> ${Number(metrics.alertsToday) || 0}`,
        `<b>\u0645\u062d\u0627\u0648\u0644\u0627\u062a \u062f\u062e\u0648\u0644 \u0641\u0627\u0634\u0644\u0629:</b> ${Number(metrics.failedLoginsToday) || 0}`,
        `<b>\u0637\u0644\u0628\u0627\u062a \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0627\u0644\u0645\u0631\u0648\u0631:</b> ${Number(metrics.resetRequestsToday) || 0}`,
        `<b>\u0639\u0646\u0627\u0648\u064a\u0646 IP \u0645\u062d\u0638\u0648\u0631\u0629:</b> ${Number(metrics.blockedIpsCount) || 0}`,
        `<b>\u062a\u0646\u0628\u064a\u0647\u0627\u062a \u063a\u064a\u0631 \u0645\u062d\u0644\u0648\u0644\u0629:</b> ${Number(metrics.unresolvedAlerts) || 0}`,
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
      await sendReply({ chatId, text: formatEventsMessage('\ud83d\udd10 \u0622\u062e\u0631 \u0645\u062d\u0627\u0648\u0644\u0627\u062a \u0627\u0644\u062f\u062e\u0648\u0644 \u0627\u0644\u0641\u0627\u0634\u0644\u0629', events) });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'reset_requests') {
      const events = await listSecurityEvents({ eventType: 'forgot_password_requested' });
      await sendReply({ chatId, text: formatEventsMessage('\ud83d\udd01 \u0622\u062e\u0631 \u0637\u0644\u0628\u0627\u062a \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631', events) });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'ack' || commandInfo.command === 'resolve') {
      const alertId = sanitizeText(commandInfo.args[0], 80);
      if (!alertId) {
        await sendReply({ chatId, text: `\u0635\u064a\u063a\u0629 \u0627\u0644\u0623\u0645\u0631 \u0627\u0644\u0635\u062d\u064a\u062d\u0629: /${commandInfo.command} <alert_id>` });
        return res.status(200).json({ ok: true });
      }

      if (commandInfo.command === 'ack') {
        await setAlertState({ alertId, patch: { read: true }, actor });
        await sendReply({ chatId, text: `\u062a\u0645 \u062a\u0639\u0644\u064a\u0645 \u0627\u0644\u062a\u0646\u0628\u064a\u0647 ${alertId} \u0643\u0645\u0642\u0631\u0648\u0621.` });
      } else {
        await setAlertState({ alertId, patch: { read: true, status: 'resolved' }, actor });
        await sendReply({ chatId, text: `\u062a\u0645 \u062a\u0639\u0644\u064a\u0645 \u0627\u0644\u062a\u0646\u0628\u064a\u0647 ${alertId} \u0643\u0645\u062d\u0644\u0648\u0644.` });
      }
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'mute' || commandInfo.command === 'unmute') {
      const eventType = sanitizeText(commandInfo.args[0], 80).toLowerCase();
      if (!eventType) {
        await sendReply({ chatId, text: `\u0635\u064a\u063a\u0629 \u0627\u0644\u0623\u0645\u0631 \u0627\u0644\u0635\u062d\u064a\u062d\u0629: /${commandInfo.command} <event_type>` });
        return res.status(200).json({ ok: true });
      }

      const current = await getSecuritySettings();
      const currentMuted = new Set(Array.isArray(current.telegram.mutedEventTypes) ? current.telegram.mutedEventTypes : []);
      if (commandInfo.command === 'mute') currentMuted.add(eventType);
      if (commandInfo.command === 'unmute') currentMuted.delete(eventType);
      await saveSecuritySettings({ telegram: { ...current.telegram, mutedEventTypes: Array.from(currentMuted) } }, actor);
      await sendReply({
        chatId,
        text: commandInfo.command === 'mute'
          ? `\u062a\u0645 \u0643\u062a\u0645 \u062a\u0646\u0628\u064a\u0647\u0627\u062a ${eventType}.`
          : `\u062a\u0645 \u0625\u0644\u063a\u0627\u0621 \u0643\u062a\u0645 \u062a\u0646\u0628\u064a\u0647\u0627\u062a ${eventType}.`,
      });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'user_sessions' || commandInfo.command === 'force_logout') {
      await sendReply({ chatId, text: '\u0647\u0630\u0627 \u0627\u0644\u0623\u0645\u0631 \u0645\u062e\u0637\u0637 \u0644\u0644\u062a\u0637\u0648\u064a\u0631 \u0641\u064a \u0627\u0644\u0645\u0631\u062d\u0644\u0629 \u0627\u0644\u062a\u0627\u0644\u064a\u0629.' });
      return res.status(200).json({ ok: true });
    }

    await sendReply({ chatId, text: '\u0627\u0644\u0623\u0645\u0631 \u063a\u064a\u0631 \u0645\u0639\u0631\u0648\u0641. \u0627\u0633\u062a\u062e\u062f\u0645 /help \u0644\u0639\u0631\u0636 \u0627\u0644\u0623\u0648\u0627\u0645\u0631 \u0627\u0644\u0645\u062a\u0627\u062d\u0629.' });
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
    await sendReply({ chatId, text: '\u062d\u062f\u062b \u062e\u0637\u0623 \u0623\u062b\u0646\u0627\u0621 \u062a\u0646\u0641\u064a\u0630 \u0627\u0644\u0623\u0645\u0631. \u062d\u0627\u0648\u0644 \u0645\u0631\u0629 \u0623\u062e\u0631\u0649.' });
    return res.status(200).json({ ok: true });
  }
}
