import React from 'react';
import { motion as Motion } from 'framer-motion';
import { AlertTriangle, PackageSearch } from 'lucide-react';

const surfaceClass = 'rounded-[1.7rem] border border-slate-200 bg-white shadow-[0_14px_34px_rgba(15,23,42,0.08)]';

const ProductsGridSkeleton = ({ count = 8 }) => (
  <div className="py-3 grid grid-cols-2 lg:grid-cols-12 gap-3 md:gap-4">
    {Array.from({ length: count }).map((_, index) => (
      <div key={`product-skeleton-${index}`} className={`${index % 3 === 0 ? 'lg:col-span-4' : 'lg:col-span-3'} ${surfaceClass} overflow-hidden`}>
        <div className="relative aspect-[4/5] bg-slate-100">
          <div className="absolute inset-0 skeleton-shimmer" />
        </div>
        <div className="p-4 space-y-3">
          <div className="h-4 rounded-lg bg-slate-100" />
          <div className="h-4 w-2/3 rounded-lg bg-slate-100" />
          <div className="h-8 rounded-xl bg-slate-100" />
        </div>
      </div>
    ))}
  </div>
);

const EmptyStateCard = ({ title, description, actionLabel, onAction, icon }) => {
  const IconComponent = icon || PackageSearch;

  return (
    <Motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className={`${surfaceClass} p-8 md:p-12 text-center`}>
      <div className="mx-auto mb-4 h-14 w-14 rounded-2xl bg-slate-100 border border-slate-200 inline-flex items-center justify-center">
        <IconComponent size={30} className="text-slate-400" />
      </div>
      <p className="text-slate-900 text-xl font-black">{title}</p>
      {description && <p className="text-slate-500 text-sm font-black mt-2">{description}</p>}
      {actionLabel && typeof onAction === 'function' && (
        <button type="button" onClick={onAction} className="mt-5 shop-btn-primary">
          {actionLabel}
        </button>
      )}
    </Motion.div>
  );
};

const ErrorStateCard = ({ title, description, actionLabel, onAction }) => (
  <Motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-[1.5rem] border border-rose-200 bg-rose-50 p-6 text-center">
    <AlertTriangle size={42} className="mx-auto mb-3 text-rose-500" />
    <p className="text-rose-800 font-black text-lg">{title}</p>
    {description && <p className="text-rose-700 text-sm font-bold mt-2">{description}</p>}
    {actionLabel && typeof onAction === 'function' && (
      <button type="button" onClick={onAction} className="mt-4 shop-btn-soft border-rose-300 text-rose-700">
        {actionLabel}
      </button>
    )}
  </Motion.div>
);

export { EmptyStateCard, ErrorStateCard, ProductsGridSkeleton };
