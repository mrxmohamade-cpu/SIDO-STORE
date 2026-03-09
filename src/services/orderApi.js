const parseResponseBody = async (response) => {
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();

  if (contentType.includes('application/json')) {
    return response.json().catch(() => null);
  }

  const text = await response.text().catch(() => '');
  return { __rawText: text };
};

const sendOrderNotification = async (order) => {
  const response = await fetch('/api/send-order', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ order }),
  });

  const payload = await parseResponseBody(response);
  if (!response.ok) {
    const payloadError = typeof payload?.error === 'string' ? payload.error.trim() : '';
    if (payloadError) {
      throw new Error(payloadError);
    }

    if (response.status === 404) {
      throw new Error('خدمة إرسال الطلبات غير متاحة حاليًا. تأكد من تشغيل API.');
    }

    throw new Error('تعذر إرسال إشعار الطلب.');
  }

  return payload || {};
};

export { sendOrderNotification };
