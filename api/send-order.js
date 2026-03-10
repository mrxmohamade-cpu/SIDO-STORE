import { formatTelegramEventMessage, sendTelegramEventNotification } from './_telegram.js';
import { buildEventFromRequest, isIpBlocked, logSecurityEvent } from './_security.js';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 12;
const ORDER_MAX_ITEMS = 30;
const NAME_MIN_LENGTH = 2;
const NAME_MAX_LENGTH = 80;

const rateLimitStore = globalThis.__sendOrderRateLimitStore || new Map();
globalThis.__sendOrderRateLimitStore = rateLimitStore;

const escapeHtml = (value = '') =>
  String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');

const sanitizeText = (value, maxLength = 120) =>
  String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);

const normalizePhone = (value) => String(value || '').replace(/[^\d+]/g, '');

const roundMoney = (value) => Math.round((Number(value) + Number.EPSILON) * 100) / 100;

const parseRequestBody = (body) => {
  if (!body) return null;

  if (typeof body === 'string') {
    try {
      return JSON.parse(body);
    } catch {
      return null;
    }
  }

  if (typeof body === 'object') {
    return body;
  }

  return null;
};

const getClientIp = (req) => {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
    return forwardedFor.split(',')[0].trim();
  }

  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string' && realIp.trim()) {
    return realIp.trim();
  }

  return req.socket?.remoteAddress || 'unknown';
};

const isRateLimited = (ip) => {
  const now = Date.now();
  const key = String(ip || 'unknown');
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  for (const [trackedIp, timestamps] of rateLimitStore.entries()) {
    const activeTimestamps = timestamps.filter((ts) => ts > windowStart);
    if (activeTimestamps.length > 0) {
      rateLimitStore.set(trackedIp, activeTimestamps);
    } else {
      rateLimitStore.delete(trackedIp);
    }
  }

  const existing = rateLimitStore.get(key) || [];
  if (existing.length >= RATE_LIMIT_MAX_REQUESTS) {
    return true;
  }

  existing.push(now);
  rateLimitStore.set(key, existing);
  return false;
};

const validateCustomer = (customer) => {
  if (!customer || typeof customer !== 'object') {
    return { ok: false, message: 'بيانات الزبون مطلوبة.' };
  }

  const name = sanitizeText(customer.name, NAME_MAX_LENGTH);
  const phone = normalizePhone(customer.phone);
  const wilaya = sanitizeText(customer.wilaya_name || customer.wilaya, 80);
  const commune = sanitizeText(customer.commune_name || customer.commune || customer.city, 80);

  if (name.length < NAME_MIN_LENGTH) {
    return { ok: false, message: 'اسم الزبون قصير جدًا.' };
  }

  if (!/^(\+?213|0)(5|6|7)\d{8}$/.test(phone)) {
    return { ok: false, message: 'رقم هاتف الزبون غير صالح.' };
  }

  if (!wilaya) {
    return { ok: false, message: 'الولاية مطلوبة.' };
  }

  if (!commune) {
    return { ok: false, message: 'البلدية مطلوبة.' };
  }

  return {
    ok: true,
    value: {
      name,
      phone,
      wilaya,
      commune,
    },
  };
};

const validateItems = (items) => {
  if (!Array.isArray(items) || items.length === 0) {
    return { ok: false, message: 'يجب اختيار منتج واحد على الأقل.' };
  }

  if (items.length > ORDER_MAX_ITEMS) {
    return { ok: false, message: 'عدد المنتجات في الطلب كبير جدًا.' };
  }

  const sanitizedItems = [];
  let computedSubtotal = 0;

  for (const item of items) {
    const name = sanitizeText(item?.name, 120);
    const qty = Number(item?.qty);
    const price = Number(item?.price);

    if (!name || !Number.isInteger(qty) || qty <= 0 || qty > 999) {
      return { ok: false, message: 'كمية أحد المنتجات غير صالحة.' };
    }

    if (!Number.isFinite(price) || price < 0 || price > 1_000_000_000) {
      return { ok: false, message: 'سعر أحد المنتجات غير صالح.' };
    }

    const lineTotal = roundMoney(qty * price);
    computedSubtotal += lineTotal;

    sanitizedItems.push({
      name,
      qty,
      price: roundMoney(price),
      selectedSize: sanitizeText(item?.selectedSize, 20),
      selectedColor: sanitizeText(item?.selectedColor, 30),
      lineTotal,
    });
  }

  return {
    ok: true,
    value: {
      items: sanitizedItems,
      computedSubtotal: roundMoney(computedSubtotal),
    },
  };
};

const validateOrderPayload = (payload) => {
  if (!payload || typeof payload !== 'object') {
    return { ok: false, message: 'بيانات الطلب غير صالحة.' };
  }

  const customerResult = validateCustomer(payload.customer);
  if (!customerResult.ok) return customerResult;

  const itemsResult = validateItems(payload.items);
  if (!itemsResult.ok) return itemsResult;

  const discountInput = Number(payload.discount);
  const shippingFeeInput = Number(payload.shippingFee);
  const totalInput = Number(payload.totalPrice);

  const subtotal = itemsResult.value.computedSubtotal;
  const discount = Number.isFinite(discountInput) && discountInput >= 0 ? roundMoney(discountInput) : 0;
  const shippingFee = Number.isFinite(shippingFeeInput) && shippingFeeInput >= 0 ? roundMoney(shippingFeeInput) : 0;

  if (discount > subtotal) {
    return { ok: false, message: 'قيمة الخصم لا يمكن أن تتجاوز المجموع الفرعي.' };
  }

  const expectedTotal = roundMoney(subtotal - discount + shippingFee);

  if (Number.isFinite(totalInput) && Math.abs(roundMoney(totalInput) - expectedTotal) > 1) {
    return { ok: false, message: 'الإجمالي النهائي للطلب غير مطابق لمجموع المنتجات والتوصيل.' };
  }

  const couponCode = sanitizeText(payload.couponCode, 40).toUpperCase();

  return {
    ok: true,
    value: {
      customer: customerResult.value,
      items: itemsResult.value.items,
      subtotal,
      discount,
      shippingFee,
      totalPrice: expectedTotal,
      couponCode,
    },
  };
};

const formatOrderMessage = (order) =>
  formatTelegramEventMessage({
    eventType: 'new_order',
    payload: order,
  });

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'الطريقة غير مسموح بها.' });
  }

  const clientIp = getClientIp(req);

  if (await isIpBlocked(clientIp)) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'rate_abuse',
        severity: 'high',
        summary: 'Blocked IP attempted to place an order.',
        source: 'send_order_api',
        status: 'blocked',
      }),
    );
    return res.status(403).json({ error: 'تم رفض الوصول.' });
  }

  if (isRateLimited(clientIp)) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'rate_abuse',
        severity: 'high',
        summary: 'Order endpoint rate limit exceeded by client.',
        source: 'send_order_api',
        status: 'throttled',
        metadata: { ipAddress: clientIp },
      }),
    );
    return res.status(429).json({ error: '\u062a\u0645 \u062a\u062c\u0627\u0648\u0632 \u0627\u0644\u062d\u062f \u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647 \u0645\u0646 \u0627\u0644\u0637\u0644\u0628\u0627\u062a. \u062d\u0627\u0648\u0644 \u0645\u0631\u0629 \u0623\u062e\u0631\u0649 \u0628\u0639\u062f \u0642\u0644\u064a\u0644.' });
  }

  const body = parseRequestBody(req.body);
  if (!body || !body.order) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'suspicious_payload',
        severity: 'high',
        summary: 'Invalid order payload received (empty or malformed body).',
        source: 'send_order_api',
        status: 'rejected',
      }),
    );
    return res.status(400).json({ error: 'بيانات الطلب المرسلة غير صالحة.' });
  }

  const validation = validateOrderPayload(body.order);
  if (!validation.ok) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'suspicious_payload',
        severity: 'medium',
        summary: 'Order validation failed.',
        source: 'send_order_api',
        status: 'rejected',
        metadata: {
          reason: sanitizeText(validation.message, 220),
        },
      }),
    );

    return res.status(400).json({ error: validation.message });
  }

  try {
    const message = formatOrderMessage(validation.value);
    const telegramResult = await sendTelegramEventNotification({
      eventType: 'new_order',
      message,
    });

    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'order_created',
        severity: 'info',
        summary: 'New order accepted and processed.',
        source: 'send_order_api',
        status: telegramResult.ok ? 'processed' : 'warning',
        metadata: {
          deliveredToTelegram: Boolean(telegramResult.delivered),
          couponCode: sanitizeText(validation.value.couponCode, 40),
          itemsCount: validation.value.items.length,
          totalPrice: validation.value.totalPrice,
        },
      }),
    );

    if (!telegramResult.ok) {
      await logSecurityEvent(
        buildEventFromRequest({
          req,
          eventType: 'api_error',
          severity: 'high',
          summary: 'Failed to deliver new order notification to Telegram.',
          source: 'send_order_api',
          status: 'failed',
          metadata: {
            telegramError: sanitizeText(telegramResult.error, 220),
          },
        }),
      );
      return res.status(502).json({ error: '\u062a\u0639\u0630\u0631 \u0625\u0631\u0633\u0627\u0644 \u0625\u0634\u0639\u0627\u0631 \u0627\u0644\u0637\u0644\u0628 \u0625\u0644\u0649 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645.' });
    }

    return res.status(200).json({
      ok: true,
      delivered: Boolean(telegramResult.delivered),
    });
  } catch (error) {
    await logSecurityEvent(
      buildEventFromRequest({
        req,
        eventType: 'api_error',
        severity: 'high',
        summary: 'Unhandled exception in send-order endpoint.',
        source: 'send_order_api',
        status: 'failed',
        metadata: {
          error: sanitizeText(error?.message, 220),
        },
      }),
    );

    return res.status(500).json({ error: '\u062d\u062f\u062b \u062e\u0637\u0623 \u063a\u064a\u0631 \u0645\u062a\u0648\u0642\u0639 \u0623\u062b\u0646\u0627\u0621 \u0645\u0639\u0627\u0644\u062c\u0629 \u0627\u0644\u0637\u0644\u0628.' });
  }
}
