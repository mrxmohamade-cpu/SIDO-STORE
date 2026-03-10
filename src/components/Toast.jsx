import React from 'react';
import { AnimatePresence, motion as Motion } from 'framer-motion';
import { AlertTriangle, CheckCircle2, Info } from 'lucide-react';

const Toast = ({ toast, transition }) => {
  const toneClass =
    toast.type === 'error'
      ? 'border-rose-200/90 bg-rose-600 text-white shadow-[0_24px_55px_rgba(190,24,93,0.35)]'
      : toast.type === 'success'
      ? 'border-emerald-200/90 bg-emerald-600 text-white shadow-[0_24px_55px_rgba(5,150,105,0.32)]'
      : 'border-slate-200/90 bg-slate-900 text-white shadow-[0_20px_44px_rgba(15,23,42,0.35)]';

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
        className="pointer-events-none fixed inset-x-0 top-0 z-[2147483647] flex justify-center px-[max(0.75rem,env(safe-area-inset-left))] pt-[max(0.75rem,env(safe-area-inset-top))]"
      >
        <div className="w-full max-w-[min(94vw,40rem)] sm:max-w-[min(92vw,40rem)]">
          <div className={`pointer-events-auto overflow-hidden rounded-[1.35rem] border px-4 py-3 backdrop-blur-xl ${toneClass}`}>
            <div className="flex items-start gap-2.5">
              <span className="mt-0.5 shrink-0">
                {toast.type === 'error' ? (
                  <AlertTriangle size={18} />
                ) : toast.type === 'success' ? (
                  <CheckCircle2 size={18} />
                ) : (
                  <Info size={18} />
                )}
              </span>
              <p className="min-w-0 whitespace-pre-wrap break-words text-sm font-black leading-6 md:text-[15px]">{message}</p>
            </div>
          </div>
        </div>
      </Motion.div>
    </AnimatePresence>
  );
};

export default Toast;
