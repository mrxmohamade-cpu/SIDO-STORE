import { getPublicSecurityStatus, isIpBlocked, logSecurityEvent } from './_security.js';
import { getClientIp, isRateLimited } from './_telegram.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 180;

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: '\u0627\u0644\u0637\u0631\u064a\u0642\u0629 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627' });
  }

  const clientIp = getClientIp(req);

  if (isRateLimited('security-public', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a. \u062d\u0627\u0648\u0644 \u0644\u0627\u062d\u0642\u064b\u0627.' });
  }

  if (await isIpBlocked(clientIp)) {
    await logSecurityEvent({
      eventType: 'route_probing',
      severity: 'high',
      source: 'security_public_api',
      summary: 'Blocked IP attempted to access public security status endpoint.',
      ipAddress: clientIp,
      endpoint: req.url,
    });

    return res.status(403).json({ error: '\u062a\u0645 \u0631\u0641\u0636 \u0627\u0644\u0648\u0635\u0648\u0644.' });
  }

  try {
    const status = await getPublicSecurityStatus();
    return res.status(200).json({ ok: true, status });
  } catch {
    return res.status(200).json({
      ok: true,
      status: {
        loginEnabled: true,
        resetPasswordEnabled: true,
        heightenedProtection: false,
      },
    });
  }
}
