const DEFAULT_MAX_SIZE_MB = 8;
const DEFAULT_TIMEOUT_MS = 30000;

const ALLOWED_IMAGE_TYPES = new Set([
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/webp',
  'image/gif',
]);

const validateImageFile = (file, options = {}) => {
  if (!(file instanceof File)) {
    return { ok: false, code: 'invalid-file', message: 'الملف غير صالح. اختر صورة صحيحة.' };
  }

  const maxSizeMb = Number(options.maxSizeMb) > 0 ? Number(options.maxSizeMb) : DEFAULT_MAX_SIZE_MB;
  const maxSizeBytes = maxSizeMb * 1024 * 1024;

  if (!ALLOWED_IMAGE_TYPES.has(file.type)) {
    return {
      ok: false,
      code: 'invalid-type',
      message: 'نوع الصورة غير مدعوم. الأنواع المسموحة: JPG, PNG, WEBP, GIF.',
    };
  }

  if (file.size <= 0) {
    return { ok: false, code: 'empty-file', message: 'الملف فارغ. اختر صورة أخرى.' };
  }

  if (file.size > maxSizeBytes) {
    return {
      ok: false,
      code: 'file-too-large',
      message: `حجم الصورة كبير. الحد الأقصى هو ${maxSizeMb}MB.`,
    };
  }

  return { ok: true };
};

const uploadImageToImgBB = (file, options = {}) => {
  const validation = validateImageFile(file, options);
  if (!validation.ok) {
    throw new Error(validation.message);
  }

  const apiKey = String(options.apiKey || '').trim();
  if (!apiKey) {
    throw new Error('مفتاح ImgBB غير موجود. أضف VITE_IMGBB_API_KEY في ملف البيئة.');
  }

  const timeoutMs = Number(options.timeoutMs) > 0 ? Number(options.timeoutMs) : DEFAULT_TIMEOUT_MS;

  const formData = new FormData();
  formData.append('image', file);
  formData.append('name', `${Date.now()}-${file.name}`.replace(/\s+/g, '-').toLowerCase());

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    xhr.open('POST', `https://api.imgbb.com/1/upload?key=${apiKey}`);
    xhr.timeout = timeoutMs;

    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable || typeof options.onProgress !== 'function') return;
      const progress = Math.min(100, Math.max(0, Math.round((event.loaded / event.total) * 100)));
      options.onProgress(progress);
    };

    xhr.onerror = () => reject(new Error('تعذر الاتصال بخدمة ImgBB. تحقق من الإنترنت.'));
    xhr.ontimeout = () => reject(new Error('انتهت مهلة رفع الصورة. حاول مجددًا.'));

    xhr.onload = () => {
      let payload = null;
      try {
        payload = JSON.parse(xhr.responseText || '{}');
      } catch {
        reject(new Error('استجابة ImgBB غير صالحة.'));
        return;
      }

      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(payload?.error?.message || `فشل رفع الصورة (HTTP ${xhr.status}).`));
        return;
      }

      const imageUrl = payload?.data?.url;
      if (!payload?.success || !imageUrl) {
        reject(new Error(payload?.error?.message || 'لم تُرجع ImgBB رابط الصورة.'));
        return;
      }

      if (typeof options.onProgress === 'function') {
        options.onProgress(100);
      }

      resolve({ imageUrl, payload });
    };

    xhr.send(formData);
  });
};

export { ALLOWED_IMAGE_TYPES, validateImageFile, uploadImageToImgBB };
