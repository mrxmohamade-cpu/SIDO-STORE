import { auth } from '../lib/firebase';

const getAdminToken = async () => {
  const user = auth?.currentUser;
  if (!user) {
    throw new Error('يجب تسجيل الدخول كمسؤول أولاً.');
  }

  return user.getIdToken();
};

const parseResponseBody = async (response) => {
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();

  if (contentType.includes('application/json')) {
    return response.json().catch(() => null);
  }

  const text = await response.text().catch(() => '');
  return { __rawText: text };
};

const resolveHttpErrorMessage = (url, response, payload) => {
  const payloadError = typeof payload?.error === 'string' ? payload.error.trim() : '';
  if (payloadError) return payloadError;

  const rawText = String(payload?.__rawText || '').trim();
  const looksLikeHtml = /^<!doctype html>|^<html/i.test(rawText);

  if (response.status === 404 && String(url).startsWith('/api/')) {
    return 'خدمة API غير متاحة محليًا. شغّل الواجهة مع API (Vite + local API routes) ثم أعد المحاولة.';
  }

  if (looksLikeHtml) {
    return 'تم استلام رد غير صالح من API. تحقق من تشغيل الخادم الخلفي بشكل صحيح.';
  }

  if (response.status === 401 || response.status === 403) {
    return 'غير مصرح لك بتنفيذ هذا الإجراء. سجّل الدخول بحساب الأدمن ثم حاول مجددًا.';
  }

  if (response.status >= 500) {
    return `حدث خطأ في الخادم (${response.status}). حاول مرة أخرى بعد قليل.`;
  }

  return `فشل تنفيذ الطلب (${response.status}).`;
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
    throw new Error('تعذر الاتصال بخدمة API. تحقق من تشغيل الخادم ثم أعد المحاولة.');
  }

  const payload = await parseResponseBody(response);
  if (!response.ok) {
    throw new Error(resolveHttpErrorMessage(url, response, payload));
  }

  return payload || {};
};

const fetchTelegramIntegration = async () => {
  const payload = await authorizedFetch('/api/telegram-integration', {
    method: 'GET',
  });

  return payload.settings || null;
};

const saveTelegramIntegration = async (settings) => {
  const payload = await authorizedFetch('/api/telegram-integration', {
    method: 'POST',
    body: JSON.stringify({
      action: 'save',
      settings,
    }),
  });

  return payload.settings || null;
};

const testTelegramIntegration = async (settings) => {
  const payload = await authorizedFetch('/api/telegram-integration', {
    method: 'POST',
    body: JSON.stringify({
      action: 'test',
      settings,
    }),
  });

  return payload.settings || null;
};

const sendAdminTelegramNotification = async (eventType, payload) => {
  await authorizedFetch('/api/telegram-notify', {
    method: 'POST',
    body: JSON.stringify({
      eventType,
      payload,
    }),
  });
};

export {
  fetchTelegramIntegration,
  saveTelegramIntegration,
  sendAdminTelegramNotification,
  testTelegramIntegration,
};
