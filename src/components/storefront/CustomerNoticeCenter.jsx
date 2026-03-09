import React, { useEffect, useMemo, useState } from 'react';
import { motion as Motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, BellRing, Info, X } from 'lucide-react';

const STORAGE_KEY = 'my_store_customer_notice_seen_v1';

const NOTICE_META = {
  normal: {
    icon: Info,
    titleClass: 'text-sky-700',
    borderClass: 'border-sky-200',
    badgeClass: 'bg-sky-100 text-sky-700',
    label: 'عادي',
  },
  important: {
    icon: BellRing,
    titleClass: 'text-amber-700',
    borderClass: 'border-amber-200',
    badgeClass: 'bg-amber-100 text-amber-700',
    label: 'مهم',
  },
  critical: {
    icon: AlertTriangle,
    titleClass: 'text-rose-700',
    borderClass: 'border-rose-200',
    badgeClass: 'bg-rose-100 text-rose-700',
    label: 'مهم جدًا',
  },
};

const readSeenMap = () => {
  if (typeof window === 'undefined') return {};

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
};

const writeSeenMap = (value) => {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
  } catch {
    // ignore local storage failures
  }
};

const isNoticeActive = (notice) => {
  if (!notice?.enabled) return false;

  const now = Date.now();
  const start = notice?.startAt ? new Date(notice.startAt).getTime() : null;
  const end = notice?.endAt ? new Date(notice.endAt).getTime() : null;

  if (Number.isFinite(start) && start > now) return false;
  if (Number.isFinite(end) && end < now) return false;
  return true;
};

const getNoticeVersionKey = (notice) => {
  const version = notice?.updatedAt || notice?.createdAt || '';
  return String(notice?.id || '') + '::' + String(version);
};

const levelOrder = { critical: 3, important: 2, normal: 1 };

const CustomerNoticeCenter = ({ notices }) => {
  const [seenMap, setSeenMap] = useState(() => readSeenMap());

  const nextNotice = useMemo(() => {
    const source = Array.isArray(notices) ? notices : [];
    return source
      .filter(isNoticeActive)
      .sort((a, b) => {
        const byPriority = Number(b.priority || 0) - Number(a.priority || 0);
        if (byPriority !== 0) return byPriority;

        const byLevel = (levelOrder[b.level] || 1) - (levelOrder[a.level] || 1);
        if (byLevel !== 0) return byLevel;

        return new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime();
      })
      .find((notice) => !seenMap[getNoticeVersionKey(notice)]);
  }, [notices, seenMap]);

  const markAsSeen = () => {
    if (!nextNotice) return;

    const key = getNoticeVersionKey(nextNotice);
    const next = {
      ...seenMap,
      [key]: Date.now(),
    };

    setSeenMap(next);
    writeSeenMap(next);
  };

  const meta = NOTICE_META[nextNotice?.level] || NOTICE_META.normal;
  const Icon = meta.icon;

  useEffect(() => {
    if (!nextNotice || typeof document === 'undefined') return undefined;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [nextNotice]);

  return (
    <AnimatePresence>
      {nextNotice && (
        <>
          <Motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[70] bg-slate-950/58 backdrop-blur-sm"
            onClick={markAsSeen}
          />

          <Motion.div
            initial={{ opacity: 0, y: 24, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 22, scale: 0.98 }}
            transition={{ duration: 0.24, ease: 'easeOut' }}
            className="fixed inset-0 z-[71] flex items-center justify-center p-3 sm:p-4 md:p-6"
            style={{
              paddingTop: 'max(0.75rem, env(safe-area-inset-top))',
              paddingBottom: 'max(0.75rem, env(safe-area-inset-bottom))',
            }}
            onClick={markAsSeen}
          >
            <div
              className={`w-full max-w-[680px] max-h-[calc(100dvh-1.5rem)] sm:max-h-[calc(100dvh-2rem)] md:max-h-[min(90dvh,760px)] rounded-[1.6rem] border ${meta.borderClass} bg-white shadow-[0_30px_70px_rgba(15,23,42,0.28)] overflow-hidden flex flex-col`}
              onClick={(event) => event.stopPropagation()}
            >
              {nextNotice.image && (
                <div className="h-44 md:h-56 w-full bg-slate-100 overflow-hidden">
                  <img src={nextNotice.image} alt={nextNotice.title || 'notice'} className="w-full h-full object-cover" loading="lazy" decoding="async" />
                </div>
              )}

              <div className="p-5 md:p-6 flex-1 overflow-y-auto overscroll-contain">
                <div className="flex items-center justify-between gap-3">
                  <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-black ${meta.badgeClass}`}>
                    <Icon size={13} /> {meta.label}
                  </span>
                  <button
                    type="button"
                    onClick={markAsSeen}
                    className="h-8 w-8 rounded-full border border-slate-200 bg-white text-slate-500 inline-flex items-center justify-center hover:bg-slate-50"
                    aria-label="إغلاق"
                  >
                    <X size={15} />
                  </button>
                </div>

                {nextNotice.title && <h3 className={`mt-3 text-xl font-black ${meta.titleClass}`}>{nextNotice.title}</h3>}
                {nextNotice.message && <p className="mt-2 text-sm md:text-base font-bold text-slate-700 leading-7 whitespace-pre-line">{nextNotice.message}</p>}

                <div className="mt-5 flex flex-wrap items-center justify-end gap-2">
                  <button type="button" onClick={markAsSeen} className="shop-btn-soft px-4 py-2.5 text-sm">
                    تخطي
                  </button>
                  <button type="button" onClick={markAsSeen} className="shop-btn-primary px-4 py-2.5 text-sm">
                    فهمت
                  </button>
                </div>
              </div>
            </div>
          </Motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default CustomerNoticeCenter;
