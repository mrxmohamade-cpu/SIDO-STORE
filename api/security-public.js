import { getPublicSecurityStatus, isIpBlocked, logSecurityEvent } from './_security.js';
import { getClientIp, isRateLimited } from './_telegram.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 180;

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientIp = getClientIp(req);

  if (isRateLimited('security-public', clientIp, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: 'Too many requests. Please retry later.' });
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

    return res.status(403).json({ error: 'Access denied.' });
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
