import { auth } from '../lib/firebase';

const parseResponseBody = async (response) => {
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();
  if (contentType.includes('application/json')) {
    return response.json().catch(() => null);
  }
  const raw = await response.text().catch(() => '');
  return { __rawText: raw };
};

const resolveApiError = (url, response, payload) => {
  const payloadError = typeof payload?.error === 'string' ? payload.error.trim() : '';
  if (payloadError) return payloadError;

  if (response.status === 404 && String(url).startsWith('/api/')) {
    return 'API endpoint not found. Ensure serverless APIs are deployed.';
  }

  if (response.status === 401 || response.status === 403) {
    return 'You are not authorized to access this resource.';
  }

  if (response.status >= 500) {
    return 'Internal server error. Please try again later.';
  }

  return `Request failed (${response.status}).`;
};

const getAdminToken = async () => {
  const user = auth?.currentUser;
  if (!user) {
    throw new Error('Admin login is required.');
  }

  return user.getIdToken();
};

const authorizedFetch = async (url, options = {}) => {
  const token = await getAdminToken();

  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    throw new Error('Unable to connect to API service.');
  }

  const payload = await parseResponseBody(response);
  if (!response.ok) {
    throw new Error(resolveApiError(url, response, payload));
  }

  return payload || {};
};

const buildQueryString = (filters = {}) => {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    params.set(key, String(value));
  });
  const query = params.toString();
  return query ? `?${query}` : '';
};

const fetchSecurityBundle = async () => {
  const payload = await authorizedFetch('/api/security-center?view=bundle', { method: 'GET' });
  return payload.bundle || null;
};

const fetchSecurityOverview = async () => {
  const payload = await authorizedFetch('/api/security-center?view=overview', { method: 'GET' });
  return payload.overview || null;
};

const fetchSecurityEvents = async (filters = {}) => {
  const query = buildQueryString({ view: 'events', ...filters });
  const payload = await authorizedFetch(`/api/security-center${query}`, { method: 'GET' });
  return Array.isArray(payload.events) ? payload.events : [];
};

const fetchSecurityAlerts = async (filters = {}) => {
  const query = buildQueryString({ view: 'alerts', ...filters });
  const payload = await authorizedFetch(`/api/security-center${query}`, { method: 'GET' });
  return Array.isArray(payload.alerts) ? payload.alerts : [];
};

const fetchSecurityAudit = async (filters = {}) => {
  const query = buildQueryString({ view: 'audit', ...filters });
  const payload = await authorizedFetch(`/api/security-center${query}`, { method: 'GET' });
  return Array.isArray(payload.audit) ? payload.audit : [];
};

const fetchBlockedIps = async () => {
  const payload = await authorizedFetch('/api/security-center?view=blocked_ips', { method: 'GET' });
  return Array.isArray(payload.blockedIps) ? payload.blockedIps : [];
};

const fetchSecuritySettings = async () => {
  const payload = await authorizedFetch('/api/security-center?view=settings', { method: 'GET' });
  return payload.settings || null;
};

const saveSecuritySettings = async (settings) => {
  const payload = await authorizedFetch('/api/security-center', {
    method: 'POST',
    body: JSON.stringify({ action: 'save_settings', settings }),
  });
  return payload.settings || null;
};

const performSecurityAction = async (action, data = {}) => {
  return authorizedFetch('/api/security-center', {
    method: 'POST',
    body: JSON.stringify({ action, ...data }),
  });
};

const logAdminSecurityAction = async (payload = {}) => {
  return performSecurityAction('log_admin_action', { payload });
};

const trackClientSecurityEvent = async (eventType, payload = {}) => {
  try {
    const response = await fetch('/api/security-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        eventType,
        ...payload,
      }),
    });

    if (!response.ok) {
      return { ok: false };
    }

    const body = await response.json().catch(() => ({}));
    return { ok: true, body };
  } catch {
    return { ok: false };
  }
};

const fetchPublicSecurityStatus = async () => {
  const fallback = {
    loginEnabled: true,
    resetPasswordEnabled: true,
    heightenedProtection: false,
    blocked: false,
    blockedUntil: '',
    blockedReason: '',
  };

  try {
    const response = await fetch('/api/security-public', {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    const payload = await parseResponseBody(response);
    if (!response.ok) {
      return payload?.status || fallback;
    }

    return payload?.status || fallback;
  } catch {
    return fallback;
  }
};

export {
  fetchBlockedIps,
  fetchPublicSecurityStatus,
  fetchSecurityAlerts,
  fetchSecurityAudit,
  fetchSecurityBundle,
  fetchSecurityEvents,
  fetchSecurityOverview,
  fetchSecuritySettings,
  logAdminSecurityAction,
  performSecurityAction,
  saveSecuritySettings,
  trackClientSecurityEvent,
};
