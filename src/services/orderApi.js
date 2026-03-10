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

    if (response.status === 403) {
      throw new Error('تم حظر الوصول مؤقتًا بسبب نشاط غير طبيعي. حاول لاحقًا أو تواصل مع الإدارة.');
    }

    if (response.status === 429) {
      throw new Error('تم تجاوز الحد المسموح به من الطلبات. انتظر قليلًا ثم حاول مجددًا.');
    }

    if (payloadError) {
      throw new Error(payloadError);
    }

    if (response.status === 404) {
      throw new Error('\u062e\u062f\u0645\u0629 \u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u0637\u0644\u0628\u0627\u062a \u063a\u064a\u0631 \u0645\u062a\u0627\u062d\u0629 \u062d\u0627\u0644\u064a\u064b\u0627. \u062a\u0623\u0643\u062f \u0645\u0646 \u062a\u0634\u063a\u064a\u0644 API.');
    }

    throw new Error('\u062a\u0639\u0630\u0631 \u0625\u0631\u0633\u0627\u0644 \u0625\u0634\u0639\u0627\u0631 \u0627\u0644\u0637\u0644\u0628.');
  }

  return payload || {};
};

export { sendOrderNotification };
