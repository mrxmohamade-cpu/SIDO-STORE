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
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientIp = getClientIp(req);

  if (isRateLimited('security-center', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: 'Too many requests. Please retry later.' });
  }

  if (await isIpBlocked(clientIp)) {
    return res.status(403).json({ error: 'Access denied.' });
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

    return res.status(authResult.status || 401).json({ error: authResult.error || 'Unauthorized.' });
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
      return res.status(400).json({ error: 'Invalid request body.' });
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
        eventType: 'system_error',
        message: [
          '<b>Security Center Test</b>',
          '',
          'Telegram routing from Security Center is working.',
          `<b>By:</b> ${sanitizeText(actor.email, 140) || 'admin'}`,
          `<b>Time:</b> ${new Date().toISOString()}`,
        ].join('\n'),
      });

      if (!sendResult.ok) {
        return res.status(502).json({ error: 'Failed to send test message.' });
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

    return res.status(400).json({ error: 'Invalid action.' });
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

    return res.status(500).json({ error: 'Failed to process Security Center request.' });
  }
}
