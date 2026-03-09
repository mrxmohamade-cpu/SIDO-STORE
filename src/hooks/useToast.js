import { useRef, useState } from 'react';

const useToast = () => {
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  const timerRef = useRef(null);

  const showToast = (message, type = 'success', duration = 3200) => {
    const normalizedMessage = String(message ?? '').trim();
    if (!normalizedMessage) return;

    if (timerRef.current) {
      window.clearTimeout(timerRef.current);
    }

    setToast({ show: true, message: normalizedMessage, type });

    timerRef.current = window.setTimeout(() => {
      setToast({ show: false, message: '', type: 'success' });
    }, Math.max(1600, Number(duration) || 3200));
  };

  return {
    toast,
    showToast,
  };
};

export { useToast };
