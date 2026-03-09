import {
  getClientIp,
  getTelegramSettingsForAdmin,
  isRateLimited,
  parseRequestBody,
  saveTelegramSettings,
  testTelegramSettings,
  verifyAdminRequest,
} from './_telegram.js';
import {
  buildEventFromRequest,
  isIpBlocked,
  logAdminAudit,
  logSecurityEvent,
} from './_security.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 40;

export default async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientIp = getClientIp(req);

  if (await isIpBlocked(clientIp)) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'endpoint_auth_violation',
        severity: 'high',
        summary: 'Blocked IP attempted to access telegram integration endpoint.',
        source: 'telegram_integration_api',
        status: 'blocked',
      }),
    );
    return res.status(403).json({ error: 'Access denied.' });
  }

  if (isRateLimited('telegram-integration', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'rate_abuse',
        severity: 'high',
        summary: 'Telegram integration endpoint hit rate limit.',
        source: 'telegram_integration_api',
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
        summary: 'Unauthorized access attempt to telegram integration endpoint.',
        source: 'telegram_integration_api',
        status: 'blocked',
      }),
    );
    return res.status(authResult.status || 401).json({ error: authResult.error || 'Unauthorized.' });
  }

  try {
    if (req.method === 'GET') {
      const settings = await getTelegramSettingsForAdmin();
      return res.status(200).json({ ok: true, settings });
    }

    const body = parseRequestBody(req.body);
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ error: 'Invalid request body.' });
    }

    const action = String(body.action || '').trim().toLowerCase();

    if (action === 'save') {
      const settings = await saveTelegramSettings(body.settings || body);

      await logAdminAudit({
        action: 'telegram_settings_saved',
        actorEmail: authResult.value?.email,
        actorUid: authResult.value?.uid,
        ipAddress: clientIp,
        targetType: 'telegram_settings',
        targetId: 'telegram_v1',
      });

      await logSecurityEvent(
        buildEventFromRequest({
          req,
          eventType: 'telegram_settings_changed',
          severity: 'high',
          summary: 'Telegram integration settings were updated.',
          source: 'telegram_integration_api',
          status: 'success',
          user: authResult.value,
        }),
      );

      return res.status(200).json({ ok: true, settings });
    }

    if (action === 'test') {
      const settings = await testTelegramSettings(body.settings || body);

      await logSecurityEvent(
        buildEventFromRequest({
          req,
          eventType: 'admin_action',
          severity: 'low',
          summary: 'Admin executed telegram integration test.',
          source: 'telegram_integration_api',
          status: 'success',
          user: authResult.value,
        }),
      );

      return res.status(200).json({ ok: true, settings, message: 'Test message sent successfully.' });
    }

    return res.status(400).json({ error: 'Invalid action.' });
  } catch (error) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'api_error',
        severity: 'high',
        summary: 'Telegram integration endpoint failed.',
        source: 'telegram_integration_api',
        status: 'failed',
        user: authResult.value,
        metadata: {
          action: String(parseRequestBody(req.body)?.action || ''),
          error: String(error?.message || ''),
        },
      }),
    );

    const message = String(error?.message || 'Failed to process Telegram integration request.');
    return res.status(400).json({ error: message });
  }
}
