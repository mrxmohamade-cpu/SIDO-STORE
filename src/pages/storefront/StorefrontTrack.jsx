import React, { useMemo, useState } from 'react';
import { motion as Motion } from 'framer-motion';
import { CheckCircle2, CircleDot, Clock3, MapPin, Package, Search, Truck, XCircle } from 'lucide-react';
import { EmptyStateCard } from '../../components/ui/StateBlocks';

const orderTimeline = {
  pending: { label: 'تم استلام الطلب', icon: CircleDot, tone: 'text-amber-500' },
  confirmed: { label: 'تم التأكيد', icon: CheckCircle2, tone: 'text-cyan-500' },
  processing: { label: 'قيد المعالجة', icon: Package, tone: 'text-indigo-500' },
  shipped: { label: 'تم الشحن', icon: Truck, tone: 'text-blue-500' },
  out_for_delivery: { label: 'في التوصيل', icon: Truck, tone: 'text-violet-500' },
  delivered: { label: 'مكتمل', icon: CheckCircle2, tone: 'text-emerald-500' },
  cancelled: { label: 'ملغي', icon: XCircle, tone: 'text-rose-500' },
};

const deliveryProgressSteps = ['pending', 'confirmed', 'processing', 'shipped', 'out_for_delivery', 'delivered'];

const StorefrontTrack = ({ orders, customerOrders, navigateTo, routes, helpers, pageTransition }) => {
  const { getOrderStatusMeta } = helpers;
  const [query, setQuery] = useState('');
  const [searched, setSearched] = useState(false);

  const mergedOrders = useMemo(() => {
    const map = new Map();
    (Array.isArray(customerOrders) ? customerOrders : []).forEach((order) => map.set(String(order.id), order));
    (Array.isArray(orders) ? orders : []).forEach((order) => map.set(String(order.id), order));
    return Array.from(map.values()).sort((a, b) => new Date(b.date || 0).getTime() - new Date(a.date || 0).getTime());
  }, [customerOrders, orders]);

  const myOrders = useMemo(
    () =>
      (Array.isArray(customerOrders) ? customerOrders : [])
        .slice()
        .sort((a, b) => new Date(b.date || 0).getTime() - new Date(a.date || 0).getTime()),
    [customerOrders],
  );

  const foundOrder = useMemo(() => {
    const normalized = String(query || '').replace(/\D/g, '');
    if (!normalized) return null;
    return mergedOrders.find((entry) => String(entry.id).includes(normalized)) || null;
  }, [mergedOrders, query]);

  const statusMeta = getOrderStatusMeta(foundOrder?.status);
  const timelineMeta = orderTimeline[foundOrder?.status] || orderTimeline.pending;
  const TimelineIcon = timelineMeta.icon;
  const currentStepIndex = foundOrder?.status === 'cancelled' ? -1 : deliveryProgressSteps.indexOf(foundOrder?.status || 'pending');

  return (
    <Motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={pageTransition} className="max-w-6xl mx-auto w-full px-4 md:px-6 py-6 md:py-10 pb-24 md:pb-10">
      <div className="rounded-[2rem] border border-cyan-200/35 bg-gradient-to-br from-slate-950 via-[#0c2141] to-[#063047] p-6 md:p-9 text-white shadow-[0_30px_80px_rgba(8,30,52,0.55)]">
        <h1 className="text-2xl md:text-4xl font-black">تتبع الطلب</h1>
        <p className="mt-2 text-sm md:text-base text-slate-200 font-bold">أدخل رقم طلبك لمعرفة آخر حالة وتفاصيل التحديث.</p>

        <div className="mt-5 flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              inputMode="numeric"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="#123456"
              className="w-full h-12 rounded-xl border border-slate-600 bg-slate-800/60 text-white pr-9 pl-4 outline-none focus:ring-2 focus:ring-emerald-400"
            />
          </div>
          <button type="button" onClick={() => setSearched(true)} className="h-12 px-6 rounded-xl bg-emerald-500 hover:bg-emerald-600 transition font-black">بحث</button>
          <button type="button" onClick={() => navigateTo(routes.home)} className="h-12 px-6 rounded-xl bg-white/10 border border-white/20 hover:bg-white/20 transition font-black">العودة للمتجر</button>
        </div>
      </div>

      <div className="mt-6 rounded-[1.8rem] border border-slate-200 bg-white p-5 md:p-6 shadow-[0_14px_35px_rgba(15,23,42,0.08)]">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-lg md:text-xl font-black text-slate-900">طلباتي</h2>
          <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-black text-amber-700">{myOrders.length}</span>
        </div>

        {myOrders.length === 0 ? (
          <p className="mt-3 rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-4 text-sm font-bold text-slate-500">
            لم يتم تسجيل طلبات في هذا المتصفح بعد.
          </p>
        ) : (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {myOrders.slice(0, 12).map((order) => {
              const orderStatus = getOrderStatusMeta(order.status);
              return (
                <button
                  type="button"
                  key={String(order.id)}
                  onClick={() => {
                    setQuery(String(order.id));
                    setSearched(true);
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                  }}
                  className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-right transition hover:-translate-y-0.5 hover:border-cyan-200 hover:bg-cyan-50/40"
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-black text-slate-900">طلب #{String(order.id).slice(-8)}</p>
                    <span className={`text-[11px] font-black px-2 py-1 rounded-full border ${orderStatus.className}`}>{orderStatus.label}</span>
                  </div>
                  <p className="mt-2 text-xs font-bold text-slate-500">{new Date(order.date).toLocaleString('ar-DZ')}</p>
                  <div className="mt-2 flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-500">الإجمالي</span>
                    <span className="text-sm font-black text-emerald-700">{Number(order.totalPrice) || 0} د.ج</span>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {!searched ? null : !foundOrder ? (
        <div className="mt-6">
          <EmptyStateCard
            title="لم يتم العثور على الطلب"
            description="تحقق من الرقم ثم أعد المحاولة."
            actionLabel="العودة للمتجر"
            onAction={() => navigateTo(routes.home)}
            icon={Package}
          />
        </div>
      ) : (
        <div className="mt-6 space-y-4">
          <div className="rounded-[1.8rem] border border-slate-200 bg-white p-5 md:p-6 shadow-[0_14px_35px_rgba(15,23,42,0.08)]">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs text-slate-500 font-black">رقم الطلب</p>
                <p className="text-xl md:text-2xl font-black text-slate-900">#{String(foundOrder.id).slice(-8)}</p>
              </div>
              <span className={`text-xs font-black px-3 py-1 rounded-full border ${statusMeta.className}`}>{statusMeta.label}</span>
            </div>

            <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 flex items-center gap-3">
              <TimelineIcon size={20} className={timelineMeta.tone} />
              <div>
                <p className="text-sm font-black text-slate-900">{timelineMeta.label}</p>
                <p className="text-xs font-bold text-slate-500">آخر تحديث: {new Date(foundOrder.date).toLocaleString('ar-DZ')}</p>
              </div>
            </div>

            {foundOrder.status !== 'cancelled' && (
              <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-3 md:p-4">
                <p className="text-xs font-black text-slate-500 mb-3">مراحل التوصيل</p>
                <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
                  {deliveryProgressSteps.map((stepKey, index) => {
                    const stepMeta = orderTimeline[stepKey] || orderTimeline.pending;
                    const StepIcon = stepMeta.icon;
                    const isDone = currentStepIndex >= index;
                    return (
                      <div
                        key={stepKey}
                        className={`rounded-xl border px-2 py-2 text-center ${isDone ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-slate-200 bg-slate-50 text-slate-400'}`}
                      >
                        <StepIcon size={14} className="mx-auto" />
                        <p className="mt-1 text-[10px] font-black">{stepMeta.label}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 mt-4 text-sm font-bold">
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">التاريخ</p>
                <p className="text-slate-900 inline-flex items-center gap-1"><Clock3 size={13} /> {new Date(foundOrder.date).toLocaleDateString('ar-DZ')}</p>
              </div>
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">الإجمالي</p>
                <p className="text-slate-900">{Number(foundOrder.totalPrice) || 0} د.ج</p>
              </div>
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">المنتجات</p>
                <p className="text-slate-900">{Array.isArray(foundOrder.items) ? foundOrder.items.length : 0}</p>
              </div>
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">الولاية</p>
                <p className="text-slate-900">{foundOrder?.customer?.wilayaName || foundOrder?.customer?.wilaya_name || '-'}</p>
              </div>
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">سعر التوصيل</p>
                <p className="text-slate-900">{Number(foundOrder.shippingFee) || 0} د.ج</p>
              </div>
            </div>
          </div>

          <div className="rounded-[1.8rem] border border-slate-200 bg-white p-5 md:p-6 shadow-[0_14px_35px_rgba(15,23,42,0.08)]">
            <h3 className="text-lg font-black text-slate-900 mb-3">تفاصيل المنتجات</h3>
            <div className="space-y-2">
              {(foundOrder.items || []).map((item, index) => (
                <div key={String(foundOrder.id) + '-' + String(index)} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 flex items-center justify-between gap-2 text-sm font-bold">
                  <div>
                    <p className="text-slate-900">{item.name}</p>
                    {(item.selectedSize || item.selectedColor) && (
                      <p className="text-xs text-slate-500">
                        {item.selectedSize ? `المقاس: ${String(item.selectedSize)}` : ''}
                        {item.selectedSize && item.selectedColor ? ' | ' : ''}
                        {item.selectedColor ? `اللون: ${String(item.selectedColor)}` : ''}
                      </p>
                    )}
                    <p className="mt-1 text-[11px] font-bold text-slate-500 inline-flex items-center gap-1">
                      <MapPin size={12} />
                      {foundOrder?.customer?.wilayaName || foundOrder?.customer?.wilaya_name || ''}
                      {(foundOrder?.customer?.communeName || foundOrder?.customer?.commune_name) ? ` - ${foundOrder?.customer?.communeName || foundOrder?.customer?.commune_name}` : ''}
                    </p>
                  </div>
                  <div className="text-left" dir="ltr">
                    <p className="text-slate-700">x{item.qty}</p>
                    <p className="text-emerald-700">{Number(item.price) || 0} د.ج</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Motion.div>
  );
};

export default StorefrontTrack;
