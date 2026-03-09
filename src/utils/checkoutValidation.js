const normalizeWhitespace = (value) => String(value || '').replace(/\s+/g, ' ').trim();
const normalizePhone = (value) => String(value || '').replace(/[^\d+]/g, '');

const validateCustomerData = (customer) => {
  const name = normalizeWhitespace(customer?.name);
  const phone = normalizePhone(customer?.phone);
  const wilayaCode = String(customer?.wilayaCode || '').trim();
  const wilayaName = normalizeWhitespace(customer?.wilayaName || customer?.wilaya || customer?.wilaya_name);
  const communeName = normalizeWhitespace(customer?.communeName || customer?.commune || customer?.commune_name || customer?.city);

  if (name.length < 2 || name.length > 80) {
    return { ok: false, message: 'الاسم يجب أن يكون بين حرفين و80 حرفًا.' };
  }

  if (!/^(\+?213|0)(5|6|7)\d{8}$/.test(phone)) {
    return { ok: false, message: 'رقم الهاتف غير صالح. مثال: 0550123456' };
  }

  if (!wilayaCode || !wilayaName) {
    return { ok: false, message: 'الرجاء اختيار الولاية.' };
  }

  if (!communeName) {
    return { ok: false, message: 'الرجاء اختيار البلدية.' };
  }

  return {
    ok: true,
    value: {
      name,
      phone,
      wilayaCode,
      wilayaName,
      communeName,
      wilaya: wilayaName,
      commune: communeName,
      city: communeName,
      wilaya_name: wilayaName,
      commune_name: communeName,
    },
  };
};

const validateStockAvailability = (cartItems, products) => {
  const issues = [];

  for (const cartItem of cartItems) {
    const matching = products.find((product) => product.id === cartItem.id);
    const availableStock = Number(matching?.stock ?? cartItem.stock ?? 0);

    if (!matching) {
      issues.push(`المنتج "${cartItem.name}" لم يعد متوفرًا.`);
      continue;
    }

    if (availableStock <= 0) {
      issues.push(`المنتج "${cartItem.name}" نفد من المخزون.`);
      continue;
    }

    if (Number(cartItem.qty) > availableStock) {
      issues.push(`الكمية المطلوبة من "${cartItem.name}" تتجاوز المخزون (${availableStock}).`);
    }
  }

  return {
    ok: issues.length === 0,
    issues,
  };
};

export { normalizePhone, validateCustomerData, validateStockAvailability };
