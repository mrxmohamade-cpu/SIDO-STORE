import React from 'react';
import { AnimatePresence, motion as Motion } from 'framer-motion';
import { AlertTriangle, CheckCircle2, Info } from 'lucide-react';

const Toast = ({ toast, transition }) => {
  const toneClass =
    toast.type === 'error'
      ? 'border-rose-200 bg-rose-600 text-white shadow-[0_24px_55px_rgba(190,24,93,0.35)]'
      : toast.type === 'success'
      ? 'border-emerald-200 bg-emerald-600 text-white shadow-[0_24px_55px_rgba(5,150,105,0.32)]'
      : 'border-slate-200 bg-slate-900 text-white shadow-[0_20px_44px_rgba(15,23,42,0.35)]';

  const message = String(toast?.message || '').trim();
  if (!toast?.show || !message) return null;

  return (
    <AnimatePresence>
      <Motion.div
        key="toast"
        role="status"
        aria-live="polite"
        initial={{ opacity: 0, y: -52, scale: 0.96 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={transition}
        exit={{ opacity: 0, y: -44, scale: 0.96 }}
        className="pointer-events-none fixed left-1/2 top-[max(env(safe-area-inset-top),0.75rem)] z-[12000] w-[min(92vw,620px)] -translate-x-1/2 px-3"
      >
        <div className={`rounded-2xl border px-4 py-3 backdrop-blur-sm ${toneClass}`}>
          <div className="flex items-start gap-2">
            <span className="mt-0.5 shrink-0">
              {toast.type === 'error' ? (
                <AlertTriangle size={18} />
              ) : toast.type === 'success' ? (
                <CheckCircle2 size={18} />
              ) : (
                <Info size={18} />
              )}
            </span>
            <p className="break-words text-sm font-black leading-relaxed md:text-[15px]">{message}</p>
          </div>
        </div>
      </Motion.div>
    </AnimatePresence>
  );
};

export default Toast;
