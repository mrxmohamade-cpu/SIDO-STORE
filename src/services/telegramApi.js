import { auth } from '../lib/firebase';

const getAdminToken = async () => {
  const user = auth?.currentUser;
  if (!user) {
    throw new Error('\u064a\u062c\u0628 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0643\u0645\u0633\u0624\u0648\u0644 \u0623\u0648\u0644\u0627\u064b.');
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
    return '\u062e\u062f\u0645\u0629 API \u063a\u064a\u0631 \u0645\u062a\u0627\u062d\u0629 \u0645\u062d\u0644\u064a\u064b\u0627. \u0634\u063a\u0651\u0644 \u0627\u0644\u0648\u0627\u062c\u0647\u0629 \u0645\u0639 API (Vite + local API routes) \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.';
  }

  if (looksLikeHtml) {
    return '\u062a\u0645 \u0627\u0633\u062a\u0644\u0627\u0645 \u0631\u062f \u063a\u064a\u0631 \u0635\u0627\u0644\u062d \u0645\u0646 API. \u062a\u062d\u0642\u0642 \u0645\u0646 \u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u062e\u0627\u062f\u0645 \u0627\u0644\u062e\u0644\u0641\u064a \u0628\u0634\u0643\u0644 \u0635\u062d\u064a\u062d.';
  }

  if (response.status === 401 || response.status === 403) {
    return '\u063a\u064a\u0631 \u0645\u0635\u0631\u062d \u0644\u0643 \u0628\u062a\u0646\u0641\u064a\u0630 \u0647\u0630\u0627 \u0627\u0644\u0625\u062c\u0631\u0627\u0621. \u0633\u062c\u0651\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0628\u062d\u0633\u0627\u0628 \u0627\u0644\u0623\u062f\u0645\u0646 \u062b\u0645 \u062d\u0627\u0648\u0644 \u0645\u062c\u062f\u062f\u064b\u0627.';
  }

  if (response.status >= 500) {
    return response.status === 502
      ? '\u062a\u0639\u0630\u0631 \u0625\u0643\u0645\u0627\u0644 \u0627\u0644\u0637\u0644\u0628 \u0645\u0646 \u062e\u062f\u0645\u0629 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645. \u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u0631\u0628\u0637 \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.'
      : `\u062d\u062f\u062b \u062e\u0637\u0623 \u0641\u064a \u0627\u0644\u062e\u0627\u062f\u0645 (${response.status}). \u062d\u0627\u0648\u0644 \u0645\u0631\u0629 \u0623\u062e\u0631\u0649 \u0628\u0639\u062f \u0642\u0644\u064a\u0644.`;
  }

  return `\u0641\u0634\u0644 \u062a\u0646\u0641\u064a\u0630 \u0627\u0644\u0637\u0644\u0628 (${response.status}).`;
};

const normalizeTelegramAdminError = (message, fallback) => {
  const normalized = String(message || '').trim();
  if (!normalized) return fallback;

  if (/encryption_secret|decrypt token|secure storage|server configuration/i.test(normalized)) {
    return '\u062a\u0639\u0630\u0631 \u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u0627\u0644\u062d\u0627\u0644\u064a. \u0623\u0643\u0645\u0644 \u0625\u0639\u062f\u0627\u062f \u0627\u0644\u062e\u0627\u062f\u0645 \u0623\u0648 \u0623\u0639\u062f \u0627\u0644\u0631\u0628\u0637 \u0645\u0646 \u0644\u0648\u062d\u0629 \u0627\u0644\u0623\u062f\u0645\u0646.';
  }

  if (/bot token is invalid for test|bot token is invalid/i.test(normalized)) {
    return '\u0631\u0645\u0632 Bot Token \u063a\u064a\u0631 \u0635\u0627\u0644\u062d. \u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u062a\u0648\u0643\u0646 \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.';
  }

  if (/chat id is invalid for test|chat id is invalid/i.test(normalized)) {
    return '\u0642\u064a\u0645\u0629 Chat ID \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629. \u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u0645\u0639\u0631\u0651\u0641 \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.';
  }

  if (/failed to send test message/i.test(normalized)) {
    return '\u0641\u0634\u0644 \u0625\u0631\u0633\u0627\u0644 \u0631\u0633\u0627\u0644\u0629 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631. \u062a\u062d\u0642\u0642 \u0645\u0646 Bot Token \u0648Chat ID \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.';
  }

  if (/telegram integration is not configured/i.test(normalized)) {
    return '\u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u063a\u064a\u0631 \u0645\u0641\u0639\u0651\u0644 \u062d\u0627\u0644\u064a\u064b\u0627. \u0627\u062d\u0641\u0638 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0631\u0628\u0637 \u0623\u0648\u0644\u064b\u0627.';
  }

  if (/failed to send telegram notification/i.test(normalized)) {
    return '\u062a\u0639\u0630\u0631 \u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u0625\u0634\u0639\u0627\u0631 \u0625\u0644\u0649 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645. \u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u0631\u0628\u0637 \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.';
  }

  return normalized;
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
    throw new Error('\u062a\u0639\u0630\u0631 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0628\u062e\u062f\u0645\u0629 API. \u062a\u062d\u0642\u0642 \u0645\u0646 \u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u062e\u0627\u062f\u0645 \u062b\u0645 \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.');
  }

  const payload = await parseResponseBody(response);
  if (!response.ok) {
    throw new Error(resolveHttpErrorMessage(url, response, payload));
  }

  return payload || {};
};

const fetchTelegramIntegration = async () => {
  let payload;
  try {
    payload = await authorizedFetch('/api/telegram-integration', {
      method: 'GET',
    });
  } catch (error) {
    throw new Error(normalizeTelegramAdminError(error?.message, '\u062a\u0639\u0630\u0631 \u062a\u062d\u0645\u064a\u0644 \u0625\u0639\u062f\u0627\u062f\u0627\u062a \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.'));
  }

  return payload.settings || null;
};

const saveTelegramIntegration = async (settings) => {
  let payload;
  try {
    payload = await authorizedFetch('/api/telegram-integration', {
      method: 'POST',
      body: JSON.stringify({
        action: 'save',
        settings,
      }),
    });
  } catch (error) {
    throw new Error(normalizeTelegramAdminError(error?.message, '\u062a\u0639\u0630\u0631 \u062d\u0641\u0638 \u0625\u0639\u062f\u0627\u062f\u0627\u062a \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.'));
  }

  return payload.settings || null;
};

const testTelegramIntegration = async (settings) => {
  let payload;
  try {
    payload = await authorizedFetch('/api/telegram-integration', {
      method: 'POST',
      body: JSON.stringify({
        action: 'test',
        settings,
      }),
    });
  } catch (error) {
    throw new Error(normalizeTelegramAdminError(error?.message, '\u0641\u0634\u0644 \u0627\u062e\u062a\u0628\u0627\u0631 \u0627\u0644\u0631\u0628\u0637 \u0645\u0639 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.'));
  }

  return payload.settings || null;
};

const disconnectTelegramIntegration = async () => {
  let payload;
  try {
    payload = await authorizedFetch('/api/telegram-integration', {
      method: 'POST',
      body: JSON.stringify({
        action: 'disconnect',
      }),
    });
  } catch (error) {
    throw new Error(normalizeTelegramAdminError(error?.message, '\u062a\u0639\u0630\u0631 \u0625\u0644\u063a\u0627\u0621 \u0631\u0628\u0637 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.'));
  }

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
  disconnectTelegramIntegration,
  fetchTelegramIntegration,
  saveTelegramIntegration,
  sendAdminTelegramNotification,
  testTelegramIntegration,
};
