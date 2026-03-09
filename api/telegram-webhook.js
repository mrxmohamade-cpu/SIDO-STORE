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
  return {
    command,
    args: rest,
    raw: normalized,
  };
};

const normalizeTelegramActor = ({ chatId, userId, username }) => ({
  email: `telegram:${userId || 'unknown'}`,
  uid: `tg:${userId || 'unknown'}`,
  ipAddress: `telegram:${chatId || 'unknown'}`,
  username: sanitizeText(username, 80),
});

const buildHelpMessage = () => [
  '<b>Security Bot Commands</b>',
  '',
  '/status - system overview',
  '/security - quick risk snapshot',
  '/alerts - latest alerts',
  '/failed_logins - recent failed logins',
  '/reset_requests - recent password reset requests',
  '/block_ip <ip> - block IP (confirmation required)',
  '/unblock_ip <ip> - unblock IP (confirmation required)',
  '/disable_reset_password - temporary disable',
  '/enable_reset_password - re-enable reset password',
  '/mute <event_type> - mute one alert type',
  '/unmute <event_type> - unmute one alert type',
  '/ack <alert_id> - mark read',
  '/resolve <alert_id> - resolve alert',
  '/help - this help',
].join('\n');

const sendReply = async ({ chatId, text }) => {
  const sendResult = await sendTelegramDirectMessage({
    chatId,
    text,
    bypassEnabled: true,
  });
  return sendResult;
};

const formatAlertsMessage = (alerts = []) => {
  if (alerts.length === 0) {
    return '<b>Alerts</b>\n\nNo unresolved alerts.';
  }

  return [
    '<b>Latest Alerts</b>',
    '',
    ...alerts.slice(0, 8).map((alert) =>
      `• <b>${sanitizeText(alert.id, 16)}</b> | ${sanitizeText(alert.severity, 12).toUpperCase()} | ${sanitizeText(alert.eventType, 42)}\n${sanitizeText(alert.summary, 110)}`,
    ),
  ].join('\n');
};

const formatEventsMessage = (title, events = []) => {
  if (events.length === 0) {
    return `<b>${title}</b>\n\nNo records.`;
  }

  return [
    `<b>${title}</b>`,
    '',
    ...events.slice(0, 8).map((event) =>
      `• ${sanitizeText(event.createdAt, 24)} | ${sanitizeText(event.ipAddress, 40)} | ${sanitizeText(event.summary, 90)}`,
    ),
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
    if (!ipAddress) {
      throw new Error('Usage: /block_ip <ip>');
    }
    await blockIpAddress({ ipAddress, reason: 'Blocked from Telegram command', actor });
    return `IP ${ipAddress} has been blocked.`;
  }

  if (command === 'unblock_ip') {
    const ipAddress = sanitizeText(args[0], 90);
    if (!ipAddress) {
      throw new Error('Usage: /unblock_ip <ip>');
    }
    await unblockIpAddress({ ipAddress, actor });
    return `IP ${ipAddress} has been unblocked.`;
  }

  if (command === 'disable_reset_password' || command === 'enable_reset_password') {
    const current = await getSecuritySettings();
    const enabled = command === 'enable_reset_password';
    await saveSecuritySettings(
      {
        controls: {
          ...current.controls,
          resetPasswordEnabled: enabled,
        },
      },
      actor,
    );
    return enabled ? 'Reset password flow has been enabled.' : 'Reset password flow has been disabled.';
  }

  return 'No action executed.';
};

const canUseCommandChannel = (settings, chatId, userId) => {
  if (!settings.telegram.allowCommands) return false;

  const allowedUsers = Array.isArray(settings.telegram.allowedTelegramUserIds)
    ? settings.telegram.allowedTelegramUserIds
    : [];
  const allowedChats = Array.isArray(settings.telegram.allowedChatIds)
    ? settings.telegram.allowedChatIds
    : [];

  if (allowedUsers.length > 0 && !allowedUsers.includes(String(userId))) {
    return false;
  }

  if (allowedChats.length > 0 && !allowedChats.includes(String(chatId))) {
    return false;
  }

  return true;
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientIp = getClientIp(req);

  if (isRateLimited('telegram-webhook', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: 'Too many requests.' });
  }

  const secretExpected = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
  if (secretExpected) {
    const secretReceived = String(req.headers['x-telegram-bot-api-secret-token'] || '').trim();
    if (!secretReceived || secretReceived !== secretExpected) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  const runtime = await resolveTelegramRuntimeConfig();
  if (!runtime.ok) {
    return res.status(503).json({ error: 'Telegram integration unavailable.' });
  }

  const body = parseRequestBody(req.body);
  if (!body || typeof body !== 'object') {
    return res.status(200).json({ ok: true });
  }

  const update = body.message || body.edited_message || body.channel_post;
  const messageText = sanitizeText(update?.text, 2600);
  const commandInfo = parseCommand(messageText);

  if (!commandInfo) {
    return res.status(200).json({ ok: true });
  }

  const chatId = String(update?.chat?.id || '').trim();
  const userId = String(update?.from?.id || '').trim();
  const username = sanitizeText(update?.from?.username || update?.from?.first_name || '', 120);

  const settings = await getSecuritySettings();
  const actor = normalizeTelegramActor({ chatId, userId, username });

  const commandRateScope = `telegram-command:${chatId || 'unknown'}`;
  if (isRateLimited(commandRateScope, clientIp, settings.telegram.commandRateLimitPerMinute, RATE_LIMIT_WINDOW_MS)) {
    await sendReply({ chatId, text: 'Rate limit exceeded for commands. Try again in a minute.' });
    return res.status(200).json({ ok: true });
  }

  if (!canUseCommandChannel(settings, chatId, userId)) {
    await logSecurityEvent({
      eventType: 'telegram_command_denied',
      severity: 'high',
      source: 'telegram_webhook',
      summary: 'Unauthorized Telegram command attempt.',
      ipAddress: clientIp,
      metadata: {
        command: commandInfo.command,
        chatId,
        userId,
      },
    });

    await sendReply({ chatId, text: 'You are not authorized to use this bot command set.' });
    return res.status(200).json({ ok: true });
  }

  await logAdminAudit({
    action: `telegram_command_${commandInfo.command}`,
    actorEmail: actor.email,
    actorUid: actor.uid,
    ipAddress: actor.ipAddress,
    targetType: 'telegram_command',
    targetId: commandInfo.command,
    metadata: {
      args: commandInfo.args,
      username,
      chatId,
      userId,
    },
  });

  await logSecurityEvent({
    eventType: 'telegram_command',
    severity: 'medium',
    source: 'telegram_webhook',
    summary: `Telegram command executed: ${commandInfo.command}`,
    ipAddress: clientIp,
    userEmail: actor.email,
    metadata: {
      command: commandInfo.command,
      chatId,
      userId,
      username,
    },
  });

  try {
    if (commandInfo.command === 'help') {
      await sendReply({ chatId, text: buildHelpMessage() });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'confirm') {
      const code = sanitizeText(commandInfo.args[0], 12);
      if (!code) {
        await sendReply({ chatId, text: 'Usage: /confirm <code>' });
        return res.status(200).json({ ok: true });
      }

      const pending = consumePendingConfirmation({ userId, code });
      if (!pending) {
        await sendReply({ chatId, text: 'Invalid or expired confirmation code.' });
        return res.status(200).json({ ok: true });
      }

      const resultMessage = await executeCommandAction({
        command: pending.action,
        args: pending.payload.args,
        actor,
      });

      await sendReply({ chatId, text: `<b>Confirmed</b>\n\n${sanitizeText(resultMessage, 220)}` });
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
          '<b>Confirmation Required</b>',
          '',
          `Command: /${commandInfo.command}`,
          `Code: <b>${code}</b>`,
          'Run /confirm <code> within 2 minutes to execute.',
        ].join('\n'),
      });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'status' || commandInfo.command === 'security') {
      const overview = await getSecurityOverview();
      const metrics = overview.metrics || {};
      const message = [
        '<b>Security Status</b>',
        '',
        `<b>Risk:</b> ${sanitizeText(metrics.riskLevel, 20).toUpperCase() || 'UNKNOWN'}`,
        `<b>Alerts Today:</b> ${Number(metrics.alertsToday) || 0}`,
        `<b>Failed Logins:</b> ${Number(metrics.failedLoginsToday) || 0}`,
        `<b>Reset Requests:</b> ${Number(metrics.resetRequestsToday) || 0}`,
        `<b>Blocked IPs:</b> ${Number(metrics.blockedIpsCount) || 0}`,
        `<b>Unresolved Alerts:</b> ${Number(metrics.unresolvedAlerts) || 0}`,
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
      await sendReply({ chatId, text: formatEventsMessage('Recent Failed Admin Logins', events) });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'reset_requests') {
      const events = await listSecurityEvents({ eventType: 'forgot_password_requested' });
      await sendReply({ chatId, text: formatEventsMessage('Recent Reset Password Requests', events) });
      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'ack' || commandInfo.command === 'resolve') {
      const alertId = sanitizeText(commandInfo.args[0], 80);
      if (!alertId) {
        await sendReply({ chatId, text: `Usage: /${commandInfo.command} <alert_id>` });
        return res.status(200).json({ ok: true });
      }

      if (commandInfo.command === 'ack') {
        await setAlertState({ alertId, patch: { read: true }, actor });
        await sendReply({ chatId, text: `Alert ${alertId} marked as read.` });
      } else {
        await setAlertState({ alertId, patch: { read: true, status: 'resolved' }, actor });
        await sendReply({ chatId, text: `Alert ${alertId} marked as resolved.` });
      }

      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'mute' || commandInfo.command === 'unmute') {
      const eventType = sanitizeText(commandInfo.args[0], 80).toLowerCase();
      if (!eventType) {
        await sendReply({ chatId, text: `Usage: /${commandInfo.command} <event_type>` });
        return res.status(200).json({ ok: true });
      }

      const current = await getSecuritySettings();
      const currentMuted = new Set(Array.isArray(current.telegram.mutedEventTypes) ? current.telegram.mutedEventTypes : []);

      if (commandInfo.command === 'mute') currentMuted.add(eventType);
      if (commandInfo.command === 'unmute') currentMuted.delete(eventType);

      await saveSecuritySettings(
        {
          telegram: {
            ...current.telegram,
            mutedEventTypes: Array.from(currentMuted),
          },
        },
        actor,
      );

      await sendReply({
        chatId,
        text: commandInfo.command === 'mute'
          ? `Event type ${eventType} is now muted.`
          : `Event type ${eventType} is now unmuted.`,
      });

      return res.status(200).json({ ok: true });
    }

    if (commandInfo.command === 'user_sessions' || commandInfo.command === 'force_logout') {
      await sendReply({
        chatId,
        text: 'Session-level commands are reserved for the next backend auth phase and are not enabled yet.',
      });
      return res.status(200).json({ ok: true });
    }

    await sendReply({ chatId, text: 'Unknown command. Use /help.' });
    return res.status(200).json({ ok: true });
  } catch (error) {
    await logSecurityEvent({
      eventType: 'api_error',
      severity: 'high',
      source: 'telegram_webhook',
      summary: 'Telegram command handler failed.',
      ipAddress: clientIp,
      userEmail: actor.email,
      metadata: {
        command: commandInfo.command,
        error: sanitizeText(error?.message, 220),
      },
    });

    await sendReply({ chatId, text: 'Command execution failed. Please try again.' });
    return res.status(200).json({ ok: true });
  }
}
