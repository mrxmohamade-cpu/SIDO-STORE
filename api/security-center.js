import {
  getClientIp,
  isRateLimited,
  parseRequestBody,
  sanitizeText,
  sendTelegramEventNotification,
  verifyAdminRequest,
} from './_telegram.js';
import {
  addIncidentAction,
  blockIpAddress,
  getSecurityOverview,
  getSecuritySettings,
  isIpBlocked,
  listAuditTrail,
  listBlockedIps,
  listSecurityAlerts,
  listSecurityEvents,
  logAdminAudit,
  logSecurityEvent,
  saveSecuritySettings,
  setAlertState,
  toCsv,
  unblockIpAddress,
} from './_security.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 120;

const parseFilters = (query = {}) => ({
  severity: sanitizeText(query.severity, 20),
  status: sanitizeText(query.status, 30),
  source: sanitizeText(query.source, 60),
  eventType: sanitizeText(query.eventType, 80),
  ip: sanitizeText(query.ip, 90),
  query: sanitizeText(query.query, 120),
  fromDate: sanitizeText(query.fromDate, 20),
  toDate: sanitizeText(query.toDate, 20),
  read: sanitizeText(query.read, 10),
});

const exportIfRequested = (res, data, exportType, filenamePrefix) => {
  if (exportType === 'json') {
    return res.status(200).json({ ok: true, data });
  }

  if (exportType === 'csv') {
    const csvBody = toCsv(data);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filenamePrefix}-${Date.now()}.csv"`);
    return res.status(200).send(csvBody);
  }

  return null;
};

const buildActor = (authValue, clientIp) => ({
  email: authValue?.email || '',
  uid: authValue?.uid || '',
  ipAddress: clientIp,
});

export default async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: '\u0627\u0644\u0637\u0631\u064a\u0642\u0629 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627.' });
  }

  const clientIp = getClientIp(req);

  if (isRateLimited('security-center', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a. \u062d\u0627\u0648\u0644 \u0644\u0627\u062d\u0642\u064b\u0627.' });
  }

  if (await isIpBlocked(clientIp)) {
    return res.status(403).json({ error: '\u062a\u0645 \u0631\u0641\u0636 \u0627\u0644\u0648\u0635\u0648\u0644.' });
  }

  const authResult = await verifyAdminRequest(req);
  if (!authResult.ok) {
    await logSecurityEvent({
      eventType: 'admin_access_denied',
      severity: 'high',
      source: 'security_center_api',
      summary: 'Unauthorized access attempt to Security Center API.',
      ipAddress: clientIp,
      endpoint: req.url,
      status: 'blocked',
    });

    return res.status(authResult.status || 401).json({ error: authResult.error || '\u064a\u062c\u0628 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0643\u0645\u0633\u0624\u0648\u0644 \u0623\u0648\u0644\u064b\u0627.' });
  }

  const actor = buildActor(authResult.value, clientIp);

  try {
    if (req.method === 'GET') {
      const view = sanitizeText(req.query?.view, 40).toLowerCase() || 'bundle';
      const exportType = sanitizeText(req.query?.export, 10).toLowerCase();
      const filters = parseFilters(req.query || {});

      if (view === 'overview') {
        const overview = await getSecurityOverview();
        return res.status(200).json({ ok: true, overview });
      }

      if (view === 'events') {
        const events = await listSecurityEvents(filters);
        const exported = exportIfRequested(res, events, exportType, 'security-events');
        if (exported) return exported;
        return res.status(200).json({ ok: true, events });
      }

      if (view === 'alerts') {
        const alerts = await listSecurityAlerts(filters);
        const exported = exportIfRequested(res, alerts, exportType, 'security-alerts');
        if (exported) return exported;
        return res.status(200).json({ ok: true, alerts });
      }

      if (view === 'audit') {
        const audit = await listAuditTrail(filters);
        const exported = exportIfRequested(res, audit, exportType, 'security-audit');
        if (exported) return exported;
        return res.status(200).json({ ok: true, audit });
      }

      if (view === 'blocked_ips') {
        const blockedIps = await listBlockedIps();
        return res.status(200).json({ ok: true, blockedIps });
      }

      if (view === 'settings') {
        const settings = await getSecuritySettings();
        return res.status(200).json({ ok: true, settings });
      }

      const [overview, settings, alerts, events, audit, blockedIps] = await Promise.all([
        getSecurityOverview(),
        getSecuritySettings(),
        listSecurityAlerts({}),
        listSecurityEvents({}),
        listAuditTrail({}),
        listBlockedIps(),
      ]);

      return res.status(200).json({
        ok: true,
        bundle: {
          overview,
          settings,
          alerts: alerts.slice(0, 100),
          events: events.slice(0, 150),
          audit: audit.slice(0, 150),
          blockedIps,
        },
      });
    }

    const body = parseRequestBody(req.body);
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ error: '\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0637\u0644\u0628 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629.' });
    }

    const action = sanitizeText(body.action, 50).toLowerCase();

    if (action === 'save_settings') {
      const settings = await saveSecuritySettings(body.settings || {}, actor);

      await logAdminAudit({
        action: 'security_settings_saved',
        actorEmail: actor.email,
        actorUid: actor.uid,
        ipAddress: actor.ipAddress,
        targetType: 'security_settings',
        targetId: 'security_center_v1',
      });

      await logSecurityEvent({
        eventType: 'admin_settings_changed',
        severity: 'high',
        source: 'security_center',
        summary: 'Security settings updated by admin.',
        ipAddress: actor.ipAddress,
        userEmail: actor.email,
        endpoint: req.url,
        metadata: {
          module: 'security_center',
          action: 'save_settings',
        },
      });

      return res.status(200).json({ ok: true, settings });
    }

    if (action === 'alert_mark_read') {
      await setAlertState({
        alertId: body.alertId,
        patch: { read: true },
        actor,
      });
      return res.status(200).json({ ok: true });
    }

    if (action === 'alert_resolve') {
      await setAlertState({
        alertId: body.alertId,
        patch: { read: true, status: 'resolved' },
        actor,
      });
      return res.status(200).json({ ok: true });
    }

    if (action === 'alert_archive') {
      await setAlertState({
        alertId: body.alertId,
        patch: { archived: true, status: 'archived', read: true },
        actor,
      });
      return res.status(200).json({ ok: true });
    }

    if (action === 'block_ip') {
      const entry = await blockIpAddress({
        ipAddress: body.ipAddress,
        reason: body.reason,
        actor,
      });
      await addIncidentAction({ action: 'block_ip', actor, payload: { ipAddress: entry.ipAddress, reason: entry.reason } });
      return res.status(200).json({ ok: true, entry });
    }

    if (action === 'unblock_ip') {
      const entry = await unblockIpAddress({
        ipAddress: body.ipAddress,
        actor,
      });
      await addIncidentAction({ action: 'unblock_ip', actor, payload: { ipAddress: entry.ipAddress } });
      return res.status(200).json({ ok: true, entry });
    }

    if (action === 'apply_control') {
      const current = await getSecuritySettings();
      const nextSettings = await saveSecuritySettings(
        {
          controls: {
            ...current.controls,
            ...(body.controls && typeof body.controls === 'object' ? body.controls : {}),
          },
        },
        actor,
      );

      await addIncidentAction({
        action: 'apply_control',
        actor,
        payload: { controls: nextSettings.controls },
      });

      await logSecurityEvent({
        eventType: 'admin_settings_changed',
        severity: 'high',
        source: 'incident_response',
        summary: 'Admin changed incident response controls.',
        ipAddress: actor.ipAddress,
        userEmail: actor.email,
        endpoint: req.url,
        metadata: {
          controls: nextSettings.controls,
        },
      });

      return res.status(200).json({ ok: true, controls: nextSettings.controls });
    }

    if (action === 'telegram_test') {
      const sendResult = await sendTelegramEventNotification({
        eventType: 'admin_action',
        message: [
          '<b>\u2705 \u0627\u062e\u062a\u0628\u0627\u0631 \u0645\u0631\u0643\u0632 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629</b>',
          '',
          '\u062a\u0645 \u0625\u0631\u0633\u0627\u0644 \u0647\u0630\u0647 \u0627\u0644\u0631\u0633\u0627\u0644\u0629 \u0645\u0646 \u0644\u0648\u062d\u0629 \u0645\u0631\u0627\u0642\u0628\u0629 \u0627\u0644\u0645\u0648\u0642\u0639 \u0644\u0644\u062a\u0623\u0643\u062f \u0645\u0646 \u0633\u0644\u0627\u0645\u0629 \u0627\u0644\u0631\u0628\u0637.',
          `<b>\ud83d\udc64 \u0628\u0648\u0627\u0633\u0637\u0629:</b> ${sanitizeText(actor.email, 140) || 'admin'}`,
          `<b>\ud83d\udd52 \u0627\u0644\u0648\u0642\u062a:</b> ${new Date().toLocaleString('ar-DZ')}`,
        ].join('\n'),
      });

      if (!sendResult.ok) {
        return res.status(502).json({ error: '\u062a\u0639\u0630\u0631 \u0625\u0631\u0633\u0627\u0644 \u0631\u0633\u0627\u0644\u0629 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631 \u0625\u0644\u0649 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.' });
      }

      return res.status(200).json({ ok: true, delivered: Boolean(sendResult.delivered) });
    }

    if (action === 'log_admin_action') {
      await logAdminAudit({
        action: sanitizeText(body.payload?.action, 120) || 'admin_action',
        actorEmail: actor.email,
        actorUid: actor.uid,
        ipAddress: actor.ipAddress,
        targetType: sanitizeText(body.payload?.targetType, 120),
        targetId: sanitizeText(body.payload?.targetId, 120),
        metadata: body.payload && typeof body.payload === 'object' ? body.payload : {},
      });

      await logSecurityEvent({
        eventType: 'admin_action',
        severity: sanitizeText(body.payload?.severity, 20) || 'low',
        source: 'admin_dashboard',
        summary: sanitizeText(body.payload?.summary, 240) || 'Admin action logged.',
        ipAddress: actor.ipAddress,
        userEmail: actor.email,
        endpoint: req.url,
        metadata: body.payload && typeof body.payload === 'object' ? body.payload : {},
      });

      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: '\u0627\u0644\u0625\u062c\u0631\u0627\u0621 \u063a\u064a\u0631 \u0645\u0639\u0631\u0648\u0641.' });
  } catch (error) {
    await logSecurityEvent({
      eventType: 'api_error',
      severity: 'high',
      source: 'security_center_api',
      summary: 'Security Center endpoint failed.',
      ipAddress: clientIp,
      userEmail: actor.email,
      endpoint: req.url,
      metadata: {
        action: req.method === 'POST' ? sanitizeText(parseRequestBody(req.body)?.action, 50) : sanitizeText(req.query?.view, 50),
        error: sanitizeText(error?.message, 220),
      },
    });

    return res.status(500).json({ error: '\u062a\u0639\u0630\u0631 \u0645\u0639\u0627\u0644\u062c\u0629 \u0637\u0644\u0628 \u0645\u0631\u0643\u0632 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629.' });
  }
}
