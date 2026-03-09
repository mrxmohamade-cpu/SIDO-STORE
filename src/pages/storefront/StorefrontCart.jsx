import React, { useMemo, useState } from 'react';
import { AnimatePresence, motion as Motion } from 'framer-motion';
import { ChevronRight, Package, ShoppingCart, Ticket, Trash2 } from 'lucide-react';
import { EmptyStateCard } from '../../components/ui/StateBlocks';

const StorefrontCart = ({
  cart,
  dispatchCart,
  navigateTo,
  siteConfig,
  showToast,
  setCheckoutPricing,
  onAddToCart,
  onRemoveFromCart,
  onCouponApplied,
  routes,
  helpers,
  pageTransition,
}) => {
  const { buildCartItemKey, normalizeCoupons, normalizeCouponCode, isCouponApplicable, isCouponExpired, isCouponExhausted } = helpers;
  const subtotal = useMemo(() => cart.reduce((sum, item) => sum + item.price * item.qty, 0), [cart]);
  const isCouponInputVisible = Boolean(siteConfig.showCouponInput);

  const availableCoupons = useMemo(
    () => normalizeCoupons(siteConfig.coupons, siteConfig.couponCode, siteConfig.couponDiscount),
    [siteConfig.coupons, siteConfig.couponCode, siteConfig.couponDiscount, normalizeCoupons],
  );

  const [couponInput, setCouponInput] = useState('');
  const [appliedCoupon, setAppliedCoupon] = useState(null);

  const activeCoupon = useMemo(() => {
    if (!isCouponInputVisible) return null;
    if (!appliedCoupon || cart.length === 0) return null;
    const linked = availableCoupons.find(
      (coupon) => coupon.id === appliedCoupon.id || normalizeCouponCode(coupon.code) === normalizeCouponCode(appliedCoupon.code),
    );
    if (!linked || !isCouponApplicable(linked)) return null;
    return linked;
  }, [appliedCoupon, availableCoupons, cart.length, isCouponInputVisible, isCouponApplicable, normalizeCouponCode]);

  const discountValue = activeCoupon ? Math.round((subtotal * activeCoupon.discount) / 100) : 0;
  const total = Math.max(0, subtotal - discountValue);

  const applyCoupon = () => {
    const normalizedInput = normalizeCouponCode(couponInput);
    if (!normalizedInput) {
      showToast('أدخل رمز كوبون صحيح', 'error');
      return;
    }

    const coupon = availableCoupons.find((entry) => normalizeCouponCode(entry.code) === normalizedInput);
    if (!coupon) {
      showToast('كود الخصم غير صحيح', 'error');
      return;
    }
    if (isCouponExpired(coupon)) {
      showToast('هذا الكوبون منتهي الصلاحية', 'error');
      return;
    }
    if (isCouponExhausted(coupon)) {
      showToast('تم استهلاك هذا الكوبون بالكامل', 'error');
      return;
    }

    setAppliedCoupon(coupon);
    onCouponApplied();
    showToast(`تم تطبيق خصم ${coupon.discount}%`, 'success');
  };

  const cancelCoupon = () => {
    setAppliedCoupon(null);
    setCouponInput('');
    showToast('تم إلغاء الكوبون', 'success');
  };

  return (
    <Motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={pageTransition} className="pb-32 md:pb-14 min-h-screen max-w-7xl mx-auto w-full md:pt-8">
      <div className="hidden md:flex justify-between items-end px-6 mb-7">
        <h2 className="text-3xl font-black text-slate-900 flex items-center gap-3"><ShoppingCart /> سلة المشتريات</h2>
      </div>

      {cart.length === 0 ? (
        <div className="px-4">
          <EmptyStateCard
            title="سلتك فارغة"
            description="ابدأ إضافة المنتجات واستمتع بتجربة شراء سلسة."
            actionLabel="تصفح المنتجات"
            onAction={() => navigateTo(routes.home)}
            icon={Package}
          />
        </div>
      ) : (
        <div className="px-4 md:px-6 flex flex-col lg:flex-row gap-6 md:gap-8">
          <div className="flex-1 space-y-3">
            <AnimatePresence>
              {cart.map((item) => {
                const stock = Number.isFinite(Number(item.stock)) ? Number(item.stock) : Number.POSITIVE_INFINITY;

                return (
                  <Motion.div
                    layout
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    key={item.cartKey || buildCartItemKey(item)}
                    className="bg-white p-3 md:p-5 rounded-[1.6rem] flex gap-4 border border-slate-200 shadow-[0_12px_30px_rgba(15,23,42,0.08)]"
                  >
                    <img src={item.image} alt={item.name} loading="lazy" decoding="async" className="w-24 h-28 md:w-28 md:h-32 object-cover rounded-2xl bg-slate-50" />
                    <div className="flex-1 flex flex-col justify-between py-1">
                      <div className="flex justify-between items-start gap-2">
                        <div>
                          <h3 className="font-black text-slate-900 text-sm md:text-base line-clamp-2 mb-1">{item.name}</h3>
                          {(item.selectedSize || item.selectedColor) && (
                            <p className="text-xs font-black text-slate-500">
                              {item.selectedSize ? `المقاس: ${item.selectedSize}` : ''}
                              {item.selectedSize && item.selectedColor ? ' | ' : ''}
                              {item.selectedColor ? `اللون: ${item.selectedColor}` : ''}
                            </p>
                          )}
                          <p className="font-black text-emerald-600 text-lg mt-2">{item.price} د.ج</p>
                        </div>
                        <button onClick={() => onRemoveFromCart(item)} className="text-slate-400 hover:text-rose-500 bg-slate-50 hover:bg-rose-50 p-2 rounded-xl transition">
                          <Trash2 size={18} />
                        </button>
                      </div>

                      <div className="flex items-center gap-4 w-fit rounded-xl p-1.5 border border-slate-200 mt-3 bg-slate-50">
                        <button onClick={() => dispatchCart({ type: 'DECREASE', payload: item })} className="w-8 h-8 md:w-9 md:h-9 bg-white rounded-lg text-slate-700 shadow-sm font-black">-</button>
                        <span className="font-black text-sm md:text-base w-7 text-center">{item.qty}</span>
                        <button
                          onClick={() => {
                            if (item.qty >= stock) {
                              showToast('وصلت للكمية المتاحة من هذا المنتج', 'error');
                              return;
                            }
                            onAddToCart(item);
                          }}
                          className="w-8 h-8 md:w-9 md:h-9 bg-white rounded-lg text-slate-700 shadow-sm font-black"
                          disabled={item.qty >= stock}
                        >
                          +
                        </button>
                      </div>
                    </div>
                  </Motion.div>
                );
              })}
            </AnimatePresence>
          </div>

          <div className="lg:w-[390px]">
            <div className="bg-white rounded-[1.8rem] p-5 md:p-7 shadow-[0_18px_40px_rgba(15,23,42,0.12)] border border-slate-200 fixed bottom-[68px] md:sticky md:top-28 left-0 w-full md:w-auto z-30 pb-safe md:pb-6">
              <h3 className="hidden md:block font-black text-xl mb-4">ملخص الطلب</h3>

              {isCouponInputVisible && (
                <div className="mb-4 rounded-2xl border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs font-black text-slate-500 mb-2 inline-flex items-center gap-1"><Ticket size={13} /> كوبون الخصم</p>
                  <div className="flex gap-2">
                    <input type="text" dir="ltr" value={couponInput} onChange={(event) => setCouponInput(event.target.value)} placeholder="COUPON" className="shop-input h-11 py-2.5 rounded-xl px-3" />
                    <Motion.button
                      type="button"
                      onClick={applyCoupon}
                      whileHover={{ scale: 1.03 }}
                      whileTap={{ scale: 0.97 }}
                      className="shop-btn-primary px-4 py-2.5 rounded-xl text-xs"
                    >
                      ?????
                    </Motion.button>
                  </div>

                  {availableCoupons.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {availableCoupons.slice(0, 3).map((coupon) => {
                        const disabled = isCouponExpired(coupon) || isCouponExhausted(coupon);
                        return (
                          <button key={coupon.id} onClick={() => setCouponInput(coupon.code)} disabled={disabled} className={`text-[11px] px-2 py-1 rounded-full border font-black ${disabled ? 'bg-slate-100 text-slate-400 border-slate-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200'}`}>
                            {coupon.code}
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {activeCoupon && (
                    <div className="mt-2 text-xs font-black text-emerald-700 flex items-center justify-between">
                      <span>تم تطبيق {activeCoupon.code}</span>
                      <button onClick={cancelCoupon} className="text-rose-500">إلغاء</button>
                    </div>
                  )}
                </div>
              )}

              <div className="space-y-2 mb-4 border-t border-slate-100 pt-3">
                <div className="flex justify-between items-center text-sm font-bold text-slate-500"><span>المجموع الفرعي</span><span>{subtotal} د.ج</span></div>
                {discountValue > 0 && <div className="flex justify-between items-center text-sm font-bold text-emerald-600"><span>الخصم</span><span>-{discountValue} د.ج</span></div>}
                <div className="flex justify-between items-center pt-2 border-t border-slate-100"><span className="text-slate-900 font-black text-sm md:text-lg">الإجمالي</span><span className="text-2xl font-black text-emerald-600">{total} <span className="text-sm">د.ج</span></span></div>
              </div>

              <Motion.button
                type="button"
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => {
                  setCheckoutPricing({
                    subtotal,
                    discount: discountValue,
                    total,
                    couponCode: activeCoupon?.code || '',
                    couponId: activeCoupon?.id || '',
                  });
                  navigateTo(routes.checkout);
                }}
                className="w-full rounded-2xl bg-slate-900 text-white font-black py-4 shadow-[0_18px_35px_rgba(15,23,42,0.3)] hover:bg-emerald-500 transition flex justify-center items-center gap-2"
              >
                ????? ????? <ChevronRight size={18} />
              </Motion.button>
            </div>
          </div>
        </div>
      )}
    </Motion.div>
  );
};

export default StorefrontCart;
