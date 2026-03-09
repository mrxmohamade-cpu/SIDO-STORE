import {
  getClientIp,
  isRateLimited,
  parseRequestBody,
  sanitizeText,
  sendTelegramEventNotification,
  verifyAdminRequest,
} from './_telegram.js';
import { buildEventFromRequest, isIpBlocked, logAdminAudit, logSecurityEvent } from './_security.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 80;

const buildMessage = (eventType, payload) => {
  const safePayload = payload && typeof payload === 'object' ? payload : {};

  if (eventType === 'order_status_changed') {
    return [
      '<b>Order Status Updated</b>',
      '',
      `<b>Order:</b> #${sanitizeText(safePayload.orderId, 40) || '-'}`,
      `<b>From:</b> ${sanitizeText(safePayload.previousStatus, 80) || '-'}`,
      `<b>To:</b> ${sanitizeText(safePayload.nextStatus, 80) || '-'}`,
      safePayload.customerName ? `<b>Customer:</b> ${sanitizeText(safePayload.customerName, 120)}` : '',
      `<b>By:</b> ${sanitizeText(safePayload.adminEmail, 120) || 'admin'}`,
    ]
      .filter(Boolean)
      .join('\n');
  }

  if (eventType === 'system_error') {
    return [
      '<b>System Alert</b>',
      '',
      `<b>Module:</b> ${sanitizeText(safePayload.module, 80) || 'admin'}`,
      `<b>Message:</b> ${sanitizeText(safePayload.message, 240) || 'Unknown error'}`,
      `<b>By:</b> ${sanitizeText(safePayload.adminEmail, 120) || 'admin'}`,
    ]
      .filter(Boolean)
      .join('\n');
  }

  return [
    '<b>Admin Action</b>',
    '',
    `<b>Action:</b> ${sanitizeText(safePayload.action, 100) || 'update'}`,
    safePayload.entity ? `<b>Entity:</b> ${sanitizeText(safePayload.entity, 100)}` : '',
    safePayload.entityId ? `<b>ID:</b> ${sanitizeText(safePayload.entityId, 60)}` : '',
    safePayload.label ? `<b>Label:</b> ${sanitizeText(safePayload.label, 140)}` : '',
    `<b>By:</b> ${sanitizeText(safePayload.adminEmail, 120) || 'admin'}`,
  ]
    .filter(Boolean)
    .join('\n');
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientIp = getClientIp(req);

  if (await isIpBlocked(clientIp)) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'endpoint_auth_violation',
        severity: 'high',
        summary: 'Blocked IP attempted to send admin notification.',
        source: 'telegram_notify_api',
        status: 'blocked',
      }),
    );
    return res.status(403).json({ error: 'Access denied.' });
  }

  if (isRateLimited('telegram-notify', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'rate_abuse',
        severity: 'high',
        summary: 'Rate limit reached on telegram notify endpoint.',
        source: 'telegram_notify_api',
        status: 'throttled',
      }),
    );
    return res.status(429).json({ error: 'Too many requests. Please retry later.' });
  }

  const authResult = await verifyAdminRequest(req);
  if (!authResult.ok) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'admin_access_denied',
        severity: 'high',
        summary: 'Unauthorized attempt to send Telegram admin notification.',
        source: 'telegram_notify_api',
        status: 'blocked',
      }),
    );
    return res.status(authResult.status || 401).json({ error: authResult.error || 'Unauthorized.' });
  }

  const body = parseRequestBody(req.body);
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid request body.' });
  }

  const eventType = sanitizeText(body.eventType, 60).toLowerCase();
  if (!eventType) {
    return res.status(400).json({ error: 'eventType is required.' });
  }

  const payload = {
    ...(body.payload || {}),
    adminEmail: authResult.value?.email || '',
  };

  const message = buildMessage(eventType, payload);

  const notifyResult = await sendTelegramEventNotification({
    eventType,
    message,
  });

  await logAdminAudit({
    action: 'telegram_notify',
    actorEmail: authResult.value?.email,
    actorUid: authResult.value?.uid,
    ipAddress: clientIp,
    targetType: 'telegram_notification',
    targetId: eventType,
    metadata: payload,
  });

  await logSecurityEvent(
    buildEventFromRequest({
      req,
      eventType: eventType === 'system_error' ? 'api_error' : 'admin_action',
      severity: eventType === 'system_error' ? 'high' : 'low',
      summary: `Telegram notify executed for event ${eventType}.`,
      source: 'telegram_notify_api',
      status: notifyResult.ok ? 'success' : 'failed',
      user: authResult.value,
      metadata: {
        eventType,
        delivered: Boolean(notifyResult.delivered),
      },
    }),
  );

  if (!notifyResult.ok) {
    return res.status(502).json({ error: 'Failed to send Telegram notification.' });
  }

  return res.status(200).json({ ok: true, delivered: Boolean(notifyResult.delivered) });
}
