import {
  getClientIp,
  isRateLimited,
  parseRequestBody,
  sanitizeText,
  verifyAdminRequest,
} from './_telegram.js';
import {
  EVENT_TYPE_SEVERITY_HINT,
  buildEventFromRequest,
  getPublicSecurityStatus,
  isIpBlocked,
  logSecurityEvent,
  normalizeSeverity,
} from './_security.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 90;

const PUBLIC_ALLOWED_EVENT_TYPES = new Set([
  'admin_login_success',
  'admin_login_failed',
  'forgot_password_requested',
  'password_reset_requested',
  'password_reset_completed',
  'admin_logout',
  'route_probing',
  'suspicious_payload',
]);

const detectSuspiciousText = (inputText) => {
  const text = String(inputText || '').toLowerCase();
  if (!text) return false;

  const patterns = [
    'union select',
    '<script',
    'javascript:',
    '../',
    'drop table',
    'or 1=1',
    'onerror=',
  ];

  return patterns.some((pattern) => text.includes(pattern));
};

const getMetadata = (body) => {
  const source = body?.metadata && typeof body.metadata === 'object' ? body.metadata : {};
  return {
    userAgent: sanitizeText(source.userAgent || '', 180),
    page: sanitizeText(source.page || '', 160),
    endpoint: sanitizeText(source.endpoint || '', 160),
    location: sanitizeText(source.location || '', 80),
    attempts: Number(source.attempts) || 0,
  };
};

export default async function handler(req, res) {
  const clientIp = getClientIp(req);

  if (req.method === 'GET') {
    try {
      const status = await getPublicSecurityStatus(clientIp);
      return res.status(200).json({ ok: true, status });
    } catch {
      return res.status(200).json({ ok: true, status: { loginEnabled: true, resetPasswordEnabled: true, heightenedProtection: false, blocked: false, blockedUntil: '', blockedReason: '' } });
    }
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: '\u0627\u0644\u0637\u0631\u064a\u0642\u0629 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627' });
  }

  if (isRateLimited('security-event', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a. \u062d\u0627\u0648\u0644 \u0644\u0627\u062d\u0642\u064b\u0627.' });
  }

  if (await isIpBlocked(clientIp)) {
    return res.status(403).json({ error: '\u062a\u0645 \u0631\u0641\u0636 \u0627\u0644\u0648\u0635\u0648\u0644.' });
  }

  const body = parseRequestBody(req.body);
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: '\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0637\u0644\u0628 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629.' });
  }

  const eventType = sanitizeText(body.eventType, 80).toLowerCase();
  if (!eventType) {
    return res.status(400).json({ error: 'eventType is required.' });
  }

  let adminUser = null;
  if (req.headers.authorization) {
    const auth = await verifyAdminRequest(req);
    if (auth.ok) {
      adminUser = auth.value;
    }
  }

  if (!adminUser && !PUBLIC_ALLOWED_EVENT_TYPES.has(eventType)) {
    return res.status(403).json({ error: 'Not allowed for public client.' });
  }

  const metadata = getMetadata(body);
  const suspicious = detectSuspiciousText(`${body.summary || ''} ${body.message || ''} ${JSON.stringify(body.metadata || {})}`);

  const eventSeverity = normalizeSeverity(
    suspicious ? 'high' : body.severity,
    EVENT_TYPE_SEVERITY_HINT[eventType] || 'medium',
  );

  const baseEvent = buildEventFromRequest({
    req,
    eventType: suspicious ? 'suspicious_payload' : eventType,
    severity: eventSeverity,
    summary: suspicious
      ? 'Suspicious payload pattern detected from client telemetry.'
      : sanitizeText(body.summary || body.message, 240) || 'Security telemetry event.',
    source: sanitizeText(body.source, 80) || (adminUser ? 'admin_frontend' : 'public_frontend'),
    status: sanitizeText(body.status, 30) || 'captured',
    metadata: {
      ...metadata,
      ...(body.metadata && typeof body.metadata === 'object' ? body.metadata : {}),
    },
    user: adminUser,
  });

  const result = await logSecurityEvent(baseEvent);

  return res.status(200).json({
    ok: true,
    eventId: result.event?.id || '',
    alertId: result.alert?.id || '',
    notified: Boolean(result.notified),
  });
}
