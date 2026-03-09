import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion as Motion } from 'framer-motion';
import { Check, CheckCircle, ChevronDown, ChevronRight, ChevronsUpDown, Package, Search, UserRound } from 'lucide-react';
import { useAlgeriaLocations } from '../../hooks/useAlgeriaLocations';
import { getWilayaNameByCode } from '../../utils/algeriaLocations';
import { validateCustomerData } from '../../utils/checkoutValidation';
import { ErrorStateCard } from '../../components/ui/StateBlocks';

const TEXT = {
  loading: '\u062c\u0627\u0631\u064a \u0627\u0644\u062a\u062d\u0645\u064a\u0644...',
  noProductsTitle: '\u0644\u0627 \u064a\u0648\u062c\u062f \u0645\u0646\u062a\u062c\u0627\u062a \u0644\u0644\u0634\u0631\u0627\u0621',
  noProductsDesc: '\u0623\u0636\u0641 \u0645\u0646\u062a\u062c\u0627\u062a \u0623\u0648\u0644\u0627\u064b \u062b\u0645 \u0639\u062f \u0644\u0625\u062a\u0645\u0627\u0645 \u0627\u0644\u0637\u0644\u0628.',
  backToShop: '\u0627\u0644\u0639\u0648\u062f\u0629 \u0644\u0644\u062a\u0633\u0648\u0642',
  checkoutTitle: '\u0625\u062a\u0645\u0627\u0645 \u0627\u0644\u0637\u0644\u0628',
  cod: '\u062f\u0641\u0639 \u0639\u0646\u062f \u0627\u0644\u0627\u0633\u062a\u0644\u0627\u0645',
  locationsErrorTitle: '\u062a\u0639\u0630\u0631 \u062a\u062d\u0645\u064a\u0644 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u0646\u0627\u0637\u0642',
  returnStore: '\u0627\u0644\u0639\u0648\u062f\u0629 \u0644\u0644\u0645\u062a\u062c\u0631',
  fullName: '\u0627\u0644\u0627\u0633\u0645 \u0648\u0627\u0644\u0644\u0642\u0628',
  fullNamePlaceholder: '\u0623\u062f\u062e\u0644 \u0627\u0644\u0627\u0633\u0645 \u0627\u0644\u0643\u0627\u0645\u0644',
  phone: '\u0631\u0642\u0645 \u0627\u0644\u0647\u0627\u062a\u0641',
  wilaya: '\u0627\u0644\u0648\u0644\u0627\u064a\u0629',
  commune: '\u0627\u0644\u0628\u0644\u062f\u064a\u0629',
  selectWilaya: '\u0627\u062e\u062a\u0631 \u0627\u0644\u0648\u0644\u0627\u064a\u0629',
  searchWilaya: '\u0627\u0628\u062d\u062b \u0639\u0646 \u0627\u0644\u0648\u0644\u0627\u064a\u0629...',
  noWilayas: '\u0644\u0627 \u062a\u0648\u062c\u062f \u0648\u0644\u0627\u064a\u0627\u062a \u0645\u0637\u0627\u0628\u0642\u0629',
  selectCommune: '\u0627\u062e\u062a\u0631 \u0627\u0644\u0628\u0644\u062f\u064a\u0629',
  searchCommune: '\u0627\u0628\u062d\u062b \u0639\u0646 \u0627\u0644\u0628\u0644\u062f\u064a\u0629...',
  noCommunes: '\u0644\u0627 \u062a\u0648\u062c\u062f \u0628\u0644\u062f\u064a\u0627\u062a \u0645\u0637\u0627\u0628\u0642\u0629',
  chooseWilayaFirst: '\u0627\u062e\u062a\u0631 \u0627\u0644\u0648\u0644\u0627\u064a\u0629 \u0623\u0648\u0644\u0627\u064b',
  dairaPrefix: '\u062f\u0627\u0626\u0631\u0629 ',
  checkoutHint: '\u0633\u064a\u062a\u0645 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0628\u0643 \u0644\u062a\u0623\u0643\u064a\u062f \u0627\u0644\u0637\u0644\u0628 \u062b\u0645 \u0627\u0644\u0634\u062d\u0646 \u0625\u0644\u0649 \u0627\u0644\u0639\u0646\u0648\u0627\u0646 \u0627\u0644\u0645\u0633\u062c\u0644.',
  submitOrder: '\u062a\u0623\u0643\u064a\u062f \u0627\u0644\u0637\u0644\u0628 \u0627\u0644\u0622\u0646',
  paymentSummary: '\u0645\u0644\u062e\u0635 \u0627\u0644\u062f\u0641\u0639',
  subtotal: '\u0627\u0644\u0645\u062c\u0645\u0648\u0639 \u0627\u0644\u0641\u0631\u0639\u064a',
  discount: '\u0627\u0644\u062e\u0635\u0645',
  total: '\u0627\u0644\u0625\u062c\u0645\u0627\u0644\u064a',
  quickSearchHint: '\u064a\u0645\u0643\u0646\u0643 \u0627\u0644\u0628\u062d\u062b \u0627\u0644\u0633\u0631\u064a\u0639 \u062f\u0627\u062e\u0644 \u0627\u0644\u0642\u0648\u0627\u0626\u0645.',
  shippingFee: '\u0633\u0639\u0631 \u0627\u0644\u062a\u0648\u0635\u064a\u0644',
  shippingApplied: '\u062a\u0648\u0635\u064a\u0644 \u0627\u0644\u0648\u0644\u0627\u064a\u0629',
  defaultShipping: '\u0627\u0641\u062a\u0631\u0627\u0636\u064a 0 \u062f.\u062c',
  currency: '\u062f.\u062c',
};

const SearchableSelect = ({
  value,
  options,
  onChange,
  placeholder,
  searchPlaceholder,
  emptyMessage,
  disabled,
  isLoading,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const containerRef = useRef(null);

  const selectedOption = useMemo(() => options.find((option) => option.value === value) || null, [options, value]);

  const filteredOptions = useMemo(() => {
    const normalizedQuery = String(query || '').trim().toLowerCase();
    if (!normalizedQuery) return options;

    return options.filter((option) => {
      const haystack = [option.label, option.search, option.meta].filter(Boolean).join(' ').toLowerCase();
      return haystack.includes(normalizedQuery);
    });
  }, [options, query]);

  useEffect(() => {
    if (!isOpen) return undefined;

    const handlePointerDown = (event) => {
      if (containerRef.current && !containerRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    window.addEventListener('pointerdown', handlePointerDown);
    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('pointerdown', handlePointerDown);
      window.removeEventListener('keydown', handleEscape);
    };
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) {
      setQuery('');
    }
  }, [isOpen]);

  const hasOptions = options.length > 0;

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => {
          if (!disabled && !isLoading && hasOptions) {
            setIsOpen((prev) => !prev);
          }
        }}
        disabled={disabled || isLoading || !hasOptions}
        className="shop-input inline-flex items-center justify-between gap-3 text-right"
      >
        <span className={`truncate ${selectedOption ? 'text-slate-800' : 'text-slate-400'}`}>
          {isLoading ? TEXT.loading : selectedOption?.label || placeholder}
        </span>
        <span className="inline-flex items-center gap-1 text-slate-400">
          <ChevronsUpDown size={16} />
        </span>
      </button>

      {isOpen && (
        <div className="absolute z-30 mt-2 w-full overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-[0_18px_50px_rgba(15,23,42,0.16)]">
          <div className="border-b border-slate-100 p-2">
            <div className="relative">
              <Search size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                autoFocus
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={searchPlaceholder}
                className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pr-9 pl-3 text-xs font-black text-slate-700 outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-100"
              />
            </div>
          </div>

          <div className="max-h-56 overflow-y-auto p-1.5">
            {filteredOptions.length === 0 ? (
              <div className="px-3 py-3 text-center text-xs font-black text-slate-500">{emptyMessage}</div>
            ) : (
              filteredOptions.map((option) => {
                const isActive = option.value === value;
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => {
                      onChange(option.value);
                      setIsOpen(false);
                    }}
                    className={`w-full rounded-xl px-3 py-2.5 text-right transition ${isActive ? 'bg-emerald-50 text-emerald-700' : 'text-slate-700 hover:bg-slate-50'}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="text-sm font-black">{option.label}</p>
                        {option.meta && <p className="mt-0.5 text-[11px] font-bold text-slate-500">{option.meta}</p>}
                      </div>
                      {isActive && <Check size={14} className="mt-0.5 shrink-0" />}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const StorefrontCheckout = ({ cart, checkoutPricing, siteConfig, onAddOrder, navigateTo, routes, pageTransition }) => {
  const { locations, isLoading: isLocationsLoading, error: locationsError } = useAlgeriaLocations(true);
  const { communesByWilaya, defaultWilayaCode } = locations;

  const [formError, setFormError] = useState('');
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    wilayaCode: '',
    wilayaName: '',
    communeName: '',
  });

  const effectiveWilayaCode = formData.wilayaCode || defaultWilayaCode;
  const effectiveWilayaName = formData.wilayaName || getWilayaNameByCode(locations, effectiveWilayaCode);
  const shippingFeesByWilaya = useMemo(
    () => (siteConfig?.shippingFeesByWilaya && typeof siteConfig.shippingFeesByWilaya === 'object' ? siteConfig.shippingFeesByWilaya : {}),
    [siteConfig?.shippingFeesByWilaya],
  );

  const wilayaSelectOptions = useMemo(
    () =>
      (locations.wilayaOptions || []).map((option) => ({
        value: option.wilaya_code,
        label: option.wilaya_name,
        search: option.wilaya_name,
        meta: String(option.wilaya_code || '').padStart(2, '0'),
      })),
    [locations.wilayaOptions],
  );

  const communesForSelectedWilaya = useMemo(
    () => communesByWilaya[effectiveWilayaCode] || [],
    [communesByWilaya, effectiveWilayaCode],
  );

  const effectiveCommuneName = useMemo(() => {
    if (!formData.communeName) return communesForSelectedWilaya[0]?.commune_name || '';
    const hasCurrentCommune = communesForSelectedWilaya.some((entry) => entry.commune_name === formData.communeName);
    return hasCurrentCommune ? formData.communeName : communesForSelectedWilaya[0]?.commune_name || '';
  }, [communesForSelectedWilaya, formData.communeName]);

  const communeSelectOptions = useMemo(
    () =>
      communesForSelectedWilaya.map((entry) => ({
        value: entry.commune_name,
        label: entry.commune_name,
        search: entry.commune_name,
        meta: entry.daira_name ? TEXT.dairaPrefix + entry.daira_name : '',
      })),
    [communesForSelectedWilaya],
  );

  const subtotalFromCart = cart.reduce((sum, item) => sum + item.price * item.qty, 0);
  const discount = Math.min(Number(checkoutPricing.discount) || 0, subtotalFromCart);
  const shippingFee = Math.max(0, Number(shippingFeesByWilaya[effectiveWilayaCode]) || 0);
  const hasCustomShippingFee = Object.prototype.hasOwnProperty.call(shippingFeesByWilaya, effectiveWilayaCode);
  const subtotalAfterDiscount = Math.max(0, subtotalFromCart - discount);
  const total = Math.max(0, subtotalAfterDiscount + shippingFee);

  const handleWilayaChange = (nextWilayaCode) => {
    const nextWilayaName = getWilayaNameByCode(locations, nextWilayaCode);
    const nextCommunes = communesByWilaya[nextWilayaCode] || [];

    setFormData((prev) => ({
      ...prev,
      wilayaCode: nextWilayaCode,
      wilayaName: nextWilayaName,
      communeName: nextCommunes[0]?.commune_name || '',
    }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();

    const validation = validateCustomerData({
      ...formData,
      wilayaCode: effectiveWilayaCode,
      wilayaName: effectiveWilayaName,
      communeName: effectiveCommuneName,
    });

    if (!validation.ok) {
      setFormError(validation.message);
      return;
    }

    setFormError('');

    onAddOrder(validation.value, cart, {
      subtotal: subtotalFromCart,
      discount,
      total,
      shippingFee,
      couponCode: checkoutPricing.couponCode || '',
      couponId: checkoutPricing.couponId || '',
    });
  };

  if (cart.length === 0) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
        <Package size={68} className="text-slate-300 mb-4" />
        <p className="text-2xl font-black text-slate-900 mb-2">{TEXT.noProductsTitle}</p>
        <p className="text-slate-500 font-bold mb-6">{TEXT.noProductsDesc}</p>
        <button onClick={() => navigateTo(routes.home)} className="shop-btn-primary px-8 py-3 rounded-full">{TEXT.backToShop}</button>
      </div>
    );
  }

  return (
    <Motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={pageTransition} className="pb-24 min-h-screen max-w-6xl mx-auto w-full md:pt-10">
      <div className="px-4 md:px-6 mb-5 md:mb-8 flex items-center justify-between">
        <div className="inline-flex items-center gap-3">
          <button onClick={() => navigateTo(routes.cart)} className="h-10 w-10 rounded-full border border-slate-200 bg-white text-slate-600 inline-flex items-center justify-center rotate-180">
            <ChevronRight size={22} />
          </button>
          <h1 className="text-2xl md:text-3xl font-black text-slate-900">{TEXT.checkoutTitle}</h1>
        </div>
        <span className="hidden md:inline-flex shop-chip bg-emerald-50 border-emerald-200 text-emerald-700">{TEXT.cod}</span>
      </div>

      <div className="px-4 md:px-6 grid grid-cols-1 lg:grid-cols-[1fr_340px] gap-4 md:gap-6">
        <form onSubmit={handleSubmit} className="rounded-[1.8rem] border border-slate-200 bg-white p-5 md:p-8 shadow-[0_14px_35px_rgba(15,23,42,0.09)] space-y-5">
          {locationsError && (
            <ErrorStateCard
              title={TEXT.locationsErrorTitle}
              description={locationsError}
              actionLabel={TEXT.returnStore}
              onAction={() => navigateTo(routes.home)}
            />
          )}

          {formError && <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-black text-rose-700">{formError}</div>}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-black text-slate-700 mb-2">{TEXT.fullName}</label>
              <input required value={formData.name} onChange={(event) => setFormData((prev) => ({ ...prev, name: event.target.value }))} className="shop-input" placeholder={TEXT.fullNamePlaceholder} />
            </div>
            <div>
              <label className="block text-sm font-black text-slate-700 mb-2">{TEXT.phone}</label>
              <input required value={formData.phone} onChange={(event) => setFormData((prev) => ({ ...prev, phone: event.target.value }))} className="shop-input" placeholder="05xxxxxxxx" inputMode="tel" />
            </div>

            <div>
              <label className="mb-2 block text-sm font-black text-slate-700">{TEXT.wilaya}</label>
              <SearchableSelect
                value={effectiveWilayaCode}
                options={wilayaSelectOptions}
                onChange={handleWilayaChange}
                placeholder={TEXT.selectWilaya}
                searchPlaceholder={TEXT.searchWilaya}
                emptyMessage={TEXT.noWilayas}
                disabled={Boolean(locationsError)}
                isLoading={isLocationsLoading}
              />
            </div>

            <div>
              <label className="mb-2 block text-sm font-black text-slate-700">{TEXT.commune}</label>
              <SearchableSelect
                value={effectiveCommuneName}
                options={communeSelectOptions}
                onChange={(nextCommune) => setFormData((prev) => ({ ...prev, communeName: nextCommune }))}
                placeholder={TEXT.selectCommune}
                searchPlaceholder={TEXT.searchCommune}
                emptyMessage={effectiveWilayaCode ? TEXT.noCommunes : TEXT.chooseWilayaFirst}
                disabled={Boolean(locationsError) || !effectiveWilayaCode}
                isLoading={isLocationsLoading}
              />
            </div>
          </div>

          <div className="space-y-2 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-xs md:text-sm font-bold text-slate-600">
            <div className="flex items-start gap-2">
              <UserRound size={16} className="mt-0.5 text-slate-500" />
              {TEXT.checkoutHint}
            </div>
            <div className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-black text-slate-700">
              <ChevronDown size={12} className="rotate-180 text-slate-400" />
              <span>{TEXT.shippingApplied}: {shippingFee} {TEXT.currency}</span>
              {!hasCustomShippingFee && <span className="text-slate-400">({TEXT.defaultShipping})</span>}
            </div>
          </div>

          <Motion.button
            type="submit"
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.98 }}
            className="shop-btn-primary w-full py-3.5 rounded-2xl text-sm md:text-base shadow-[0_18px_40px_rgba(16,185,129,0.35)]"
          >
            <CheckCircle size={18} /> {TEXT.submitOrder}
          </Motion.button>
        </form>

        <aside className="rounded-[1.8rem] border border-slate-200 bg-white p-5 md:p-6 shadow-[0_14px_35px_rgba(15,23,42,0.09)] h-fit">
          <h3 className="text-lg font-black text-slate-900 mb-4">{TEXT.paymentSummary}</h3>
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between font-bold text-slate-500"><span>{TEXT.subtotal}</span><span>{subtotalFromCart} {TEXT.currency}</span></div>
            {discount > 0 && <div className="flex items-center justify-between font-bold text-emerald-600"><span>{TEXT.discount}</span><span>-{discount} {TEXT.currency}</span></div>}
            <div className="flex items-center justify-between font-bold text-cyan-700"><span>{TEXT.shippingFee}</span><span>{shippingFee} {TEXT.currency}</span></div>
            <div className="pt-3 border-t border-slate-100 flex items-center justify-between"><span className="font-black text-slate-900">{TEXT.total}</span><span className="font-black text-2xl text-emerald-600">{total} {TEXT.currency}</span></div>
          </div>

          <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] font-black text-slate-600 inline-flex items-center gap-1.5">
            <ChevronDown size={13} className="rotate-180" />
            <span className="inline-flex items-center gap-1"><Search size={12} /> {TEXT.quickSearchHint}</span>
          </div>
        </aside>
      </div>
    </Motion.div>
  );
};

export default StorefrontCheckout;
