import {
  disconnectTelegramSettings,
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
    return res.status(405).json({ error: '\u0627\u0644\u0637\u0631\u064a\u0642\u0629 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627.' });
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
    return res.status(403).json({ error: '\u062a\u0645 \u0631\u0641\u0636 \u0627\u0644\u0648\u0635\u0648\u0644.' });
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
    return res.status(429).json({ error: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a. \u0627\u0646\u062a\u0638\u0631 \u0642\u0644\u064a\u0644\u064b\u0627.' });
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
    return res.status(authResult.status || 401).json({ error: authResult.error || '\u064a\u062c\u0628 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0643\u0645\u0633\u0624\u0648\u0644 \u0623\u0648\u0644\u064b\u0627.' });
  }

  try {
    if (req.method === 'GET') {
      const settings = await getTelegramSettingsForAdmin();
      return res.status(200).json({ ok: true, settings });
    }

    const body = parseRequestBody(req.body);
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ error: '\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0637\u0644\u0628 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629.' });
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

      return res.status(200).json({ ok: true, settings, message: '\u062a\u0645 \u0625\u0631\u0633\u0627\u0644 \u0631\u0633\u0627\u0644\u0629 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631 \u0628\u0646\u062c\u0627\u062d.' });
    }

    if (action === 'disconnect') {
      const settings = await disconnectTelegramSettings();

      await logAdminAudit({
        action: 'telegram_settings_disconnected',
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
          summary: 'Telegram integration was disconnected by admin.',
          source: 'telegram_integration_api',
          status: 'success',
          user: authResult.value,
        }),
      );

      return res.status(200).json({ ok: true, settings, message: '\u062a\u0645 \u0641\u0635\u0644 \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u0628\u0646\u062c\u0627\u062d.' });
    }

    return res.status(400).json({ error: '\u0627\u0644\u0625\u062c\u0631\u0627\u0621 \u0627\u0644\u0645\u0637\u0644\u0648\u0628 \u063a\u064a\u0631 \u0645\u0639\u0631\u0648\u0641.' });
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

    const message = String(error?.message || '\u062a\u0639\u0630\u0631 \u0625\u0643\u0645\u0627\u0644 \u0625\u0639\u062f\u0627\u062f\u0627\u062a \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.');
    return res.status(400).json({ error: message });
  }
}
