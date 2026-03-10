import {
  formatTelegramEventMessage,
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

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: '\u0627\u0644\u0637\u0631\u064a\u0642\u0629 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627.' });
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
    return res.status(403).json({ error: '\u062a\u0645 \u0631\u0641\u0636 \u0627\u0644\u0648\u0635\u0648\u0644.' });
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
    return res.status(429).json({ error: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a. \u0627\u0646\u062a\u0638\u0631 \u0642\u0644\u064a\u0644\u064b\u0627.' });
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
    return res.status(authResult.status || 401).json({ error: authResult.error || '\u064a\u062c\u0628 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0643\u0645\u0633\u0624\u0648\u0644 \u0623\u0648\u0644\u064b\u0627.' });
  }

  const body = parseRequestBody(req.body);
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: '\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0637\u0644\u0628 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629.' });
  }

  const eventType = sanitizeText(body.eventType, 60).toLowerCase();
  if (!eventType) {
    return res.status(400).json({ error: '\u0646\u0648\u0639 \u0627\u0644\u0625\u0634\u0639\u0627\u0631 \u0645\u0637\u0644\u0648\u0628.' });
  }

  const payload = {
    ...(body.payload || {}),
    adminEmail: authResult.value?.email || '',
  };

  const message = formatTelegramEventMessage({ eventType, payload });

  const notifyResult = await sendTelegramEventNotification({
    eventType,
    message,
    payload,
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
    return res.status(502).json({ error: '\u062a\u0639\u0630\u0631 \u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u0625\u0634\u0639\u0627\u0631 \u0625\u0644\u0649 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.' });
  }

  return res.status(200).json({ ok: true, delivered: Boolean(notifyResult.delivered) });
}
