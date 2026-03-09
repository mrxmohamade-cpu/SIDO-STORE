import React, { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion as Motion } from 'framer-motion';
import {
  ArrowUpDown,
  BadgePercent,
  ChevronRight,
  Eye,
  Filter,
  Flame,
  Heart,
  Palette,
  Plus,
  Ruler,
  Search,
  Sparkles,
  Star,
} from 'lucide-react';
import { EmptyStateCard, ProductsGridSkeleton } from '../../components/ui/StateBlocks';

const getProductImages = (product) => {
  const source = Array.isArray(product?.images) ? product.images : [];
  const list = source.map((entry) => String(entry || '').trim()).filter(Boolean);
  if (list.length > 0) return list;
  const cover = String(product?.image || '').trim();
  return cover ? [cover] : [];
};

const getPrimaryImage = (product) => getProductImages(product)[0] || '';

const ProductPreviewSheet = ({
  product,
  isOpen,
  onClose,
  variants,
  selection,
  onSelectSize,
  onSelectColor,
  quantity,
  setQuantity,
  onAddToCart,
  colorPresets,
  discountPercent,
  inStock,
  previewImages,
  currentImageIndex,
  setCurrentImageIndex,
}) => {
  if (!product) return null;

  const sheetImages = Array.isArray(previewImages) && previewImages.length > 0
    ? previewImages
    : getProductImages(product);
  const maxImageIndex = Math.max(0, sheetImages.length - 1);
  const safeImageIndex = Math.min(currentImageIndex, maxImageIndex);
  const currentImage = sheetImages[safeImageIndex] || getPrimaryImage(product);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <Motion.button
            type="button"
            aria-label="إغلاق"
            className="fixed inset-0 z-[80] bg-slate-950/60 backdrop-blur-[2px]"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <Motion.div
            role="dialog"
            aria-modal="true"
            initial={{ opacity: 0, y: 40, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 32, scale: 0.98 }}
            transition={{ duration: 0.28, ease: 'easeOut' }}
            className="fixed inset-0 z-[81] flex items-end justify-center overflow-y-auto overscroll-contain p-2 md:items-center md:p-6"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="w-full md:max-w-4xl max-h-[calc(100dvh-0.9rem)] md:max-h-[88dvh] rounded-[2rem] border border-slate-200/60 bg-white shadow-[0_40px_100px_rgba(15,23,42,0.22)] overflow-hidden flex flex-col">
              <div className="grid grid-cols-1 md:grid-cols-[1.1fr_1fr] overflow-y-auto overscroll-contain">
                <div className="relative bg-gradient-to-br from-slate-100 via-white to-cyan-50 min-h-[300px] p-3 md:p-4">
                  <div className="relative h-full w-full overflow-hidden rounded-2xl">
                    <img src={currentImage} alt={product.name} className="h-full w-full object-cover" loading="lazy" decoding="async" />
                    {discountPercent > 0 && (
                      <span className="absolute top-3 right-3 rounded-full bg-rose-500 px-3 py-1 text-xs font-black text-white shadow-lg">
                        خصم {discountPercent}%
                      </span>
                    )}
                    {sheetImages.length > 1 && (
                      <>
                        <button
                          type="button"
                          onClick={() => setCurrentImageIndex((prev) => (prev - 1 + sheetImages.length) % sheetImages.length)}
                          className="absolute right-2 top-1/2 -translate-y-1/2 h-8 w-8 rounded-full border border-white/40 bg-slate-950/55 text-white inline-flex items-center justify-center"
                        >
                          <ChevronRight size={14} />
                        </button>
                        <button
                          type="button"
                          onClick={() => setCurrentImageIndex((prev) => (prev + 1) % sheetImages.length)}
                          className="absolute left-2 top-1/2 -translate-y-1/2 h-8 w-8 rounded-full border border-white/40 bg-slate-950/55 text-white inline-flex items-center justify-center"
                        >
                          <ChevronRight size={14} className="rotate-180" />
                        </button>
                      </>
                    )}
                  </div>

                  {sheetImages.length > 1 && (
                    <div className="mt-3 flex gap-2 overflow-x-auto no-scrollbar pb-1">
                      {sheetImages.map((imageUrl, index) => (
                        <button
                          key={imageUrl + '-' + String(index)}
                          type="button"
                          onClick={() => setCurrentImageIndex(index)}
                          className={`shrink-0 h-16 w-16 overflow-hidden rounded-xl border transition ${safeImageIndex === index ? 'border-slate-900 ring-2 ring-slate-900/20' : 'border-slate-200'}`}
                        >
                          <img src={imageUrl} alt={product.name} className="h-full w-full object-cover" loading="lazy" decoding="async" />
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <div className="p-5 md:p-7 space-y-4 pb-[max(1.25rem,env(safe-area-inset-bottom))]">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="shop-chip">{product.category}</p>
                      <h3 className="mt-3 text-xl md:text-2xl font-black text-slate-900 leading-snug">{product.name}</h3>
                      {product.description && (
                        <p className="mt-2 text-xs md:text-sm font-bold text-slate-500 leading-6 whitespace-pre-line line-clamp-3">
                          {product.description}
                        </p>
                      )}
                    </div>
                    <button type="button" className="shop-btn-soft px-3 py-2" onClick={onClose}>إغلاق</button>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-2xl font-black text-slate-900">{product.price} د.ج</p>
                    {discountPercent > 0 && <p className="text-sm font-bold text-slate-400 line-through">{product.oldPrice} د.ج</p>}
                  </div>

                  {variants.enableSizes && (
                    <div>
                      <p className="text-xs font-black text-slate-500 mb-2 inline-flex items-center gap-1"><Ruler size={13} /> المقاس</p>
                      <div className="flex flex-wrap gap-2">
                        {variants.sizes.map((size) => (
                          <button
                            key={size}
                            type="button"
                            onClick={() => onSelectSize(size)}
                            className={`rounded-xl px-3 py-2 text-xs font-black border transition ${selection.size === size ? 'border-slate-900 bg-slate-900 text-white' : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300'}`}
                          >
                            {size}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {variants.enableColors && (
                    <div>
                      <p className="text-xs font-black text-slate-500 mb-2 inline-flex items-center gap-1"><Palette size={13} /> اللون</p>
                      <div className="flex flex-wrap gap-2">
                        {variants.colors.map((colorName) => {
                          const preset = colorPresets.find((entry) => entry.name === colorName);
                          const isSelected = selection.color === colorName;
                          return (
                            <button
                              key={colorName}
                              type="button"
                              onClick={() => onSelectColor(colorName)}
                              className={`inline-flex items-center gap-2 rounded-xl px-3 py-2 text-xs font-black border transition ${isSelected ? 'border-slate-900 bg-slate-900 text-white' : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300'}`}
                            >
                              <span className="h-3.5 w-3.5 rounded-full border border-slate-300" style={{ backgroundColor: preset?.hex || '#e2e8f0' }} />
                              {colorName}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  <div className="flex items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white p-3">
                    <p className="text-sm font-black text-slate-700">الكمية</p>
                    <div className="inline-flex items-center gap-2">
                      <button type="button" className="h-9 w-9 rounded-xl border border-slate-200 bg-slate-50 font-black text-slate-700" onClick={() => setQuantity((prev) => Math.max(1, prev - 1))}>-</button>
                      <span className="w-8 text-center font-black text-slate-900">{quantity}</span>
                      <button type="button" className="h-9 w-9 rounded-xl border border-slate-200 bg-slate-50 font-black text-slate-700" onClick={() => setQuantity((prev) => Math.min(inStock, prev + 1))} disabled={quantity >= inStock}>+</button>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={onAddToCart}
                    disabled={inStock <= 0}
                    className={`w-full rounded-2xl px-4 py-3.5 text-sm font-black transition ${inStock <= 0 ? 'bg-slate-200 text-slate-500 cursor-not-allowed' : 'bg-slate-900 text-white shadow-[0_12px_30px_rgba(15,23,42,0.25)] hover:bg-emerald-500'}`}
                  >
                    {inStock <= 0 ? 'غير متوفر' : 'إضافة للسلة الآن'}
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

const DiscoveryCard = ({ product, isFavorite, stock, onToggleFavorite, onQuickAdd, onOpenPreview, productOnSale, discountPercent }) => {
  const stockState = stock <= 0
    ? { label: 'نفد المخزون', className: 'bg-rose-100 text-rose-700 border-rose-200' }
    : stock <= 3
    ? { label: `متبقي ${stock}`, className: 'bg-amber-100 text-amber-700 border-amber-200' }
    : { label: `متوفر ${stock}`, className: 'bg-emerald-100 text-emerald-700 border-emerald-200' };

  return (
    <Motion.article
      layout
      initial={{ opacity: 0, y: 18, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: 12, scale: 0.97 }}
      transition={{ duration: 0.28, ease: 'easeOut' }}
      className="group relative overflow-hidden rounded-[1.8rem] border border-slate-200/70 bg-white shadow-[0_14px_38px_rgba(15,23,42,0.1)]"
    >
      <div className="relative aspect-[4/5] overflow-hidden bg-slate-100">
        <img src={getPrimaryImage(product)} alt={product.name} loading="lazy" decoding="async" className="h-full w-full object-cover transition-transform duration-700 group-hover:scale-110" />
        <div className="absolute inset-0 bg-gradient-to-t from-slate-950/60 via-slate-950/10 to-transparent opacity-80" />

        <div className="absolute right-3 top-3 inline-flex items-center gap-1 rounded-full border border-white/40 bg-white/90 px-2 py-1 text-[10px] font-black text-slate-800 backdrop-blur">
          <Sparkles size={11} /> {product.category}
        </div>

        <button type="button" onClick={onToggleFavorite} className="absolute left-3 top-3 h-9 w-9 rounded-full border border-white/40 bg-white/90 backdrop-blur inline-flex items-center justify-center transition hover:scale-110">
          <Heart size={15} className={isFavorite ? 'fill-rose-500 text-rose-500' : 'text-slate-500'} />
        </button>

        {productOnSale && <span className="absolute left-3 bottom-3 rounded-full bg-rose-500 px-2.5 py-1 text-[11px] font-black text-white shadow-lg">-{discountPercent}%</span>}
        <span className={`absolute right-3 bottom-3 rounded-full border px-2.5 py-1 text-[11px] font-black ${stockState.className}`}>{stockState.label}</span>

        <div className="absolute inset-x-3 bottom-3 translate-y-16 opacity-0 transition-all duration-300 group-hover:translate-y-0 group-hover:opacity-100">
          <div className="grid grid-cols-2 gap-2 rounded-2xl border border-white/35 bg-white/90 p-2 backdrop-blur">
            <button type="button" onClick={onOpenPreview} className="rounded-xl bg-white px-3 py-2 text-xs font-black text-slate-700 hover:bg-slate-50"><span className="inline-flex items-center gap-1"><Eye size={13} /> معاينة</span></button>
            <button type="button" onClick={onQuickAdd} disabled={stock <= 0} className={`rounded-xl px-3 py-2 text-xs font-black ${stock <= 0 ? 'bg-slate-200 text-slate-500' : 'bg-slate-900 text-white'}`}><span className="inline-flex items-center gap-1"><Plus size={13} /> للسلة</span></button>
          </div>
        </div>
      </div>

      <div className="p-4">
        <h3 className="line-clamp-2 min-h-[44px] text-sm md:text-base font-black text-slate-900">{product.name}</h3>
        {product.description && <p className="mt-1 line-clamp-2 text-[11px] md:text-xs font-bold text-slate-500">{product.description}</p>}
        <div className="mt-2 flex items-end justify-between gap-2">
          <div>
            <p className="text-xl font-black text-slate-900">{product.price} د.ج</p>
            {productOnSale && <p className="text-xs font-bold text-slate-400 line-through">{product.oldPrice} د.ج</p>}
          </div>
          <button type="button" onClick={onQuickAdd} disabled={stock <= 0} className={`md:hidden rounded-xl px-3 py-2 text-xs font-black ${stock <= 0 ? 'bg-slate-200 text-slate-500' : 'bg-emerald-500 text-white'}`}>إضافة</button>
        </div>
      </div>
    </Motion.article>
  );
};
const StorefrontHome = ({
  products,
  onAddToCart,
  showToast,
  searchQuery,
  setSearchQuery,
  favorites,
  toggleFavorite,
  isLoadingProducts,
  currentRoute,
  navigateTo,
  siteConfig,
  routes,
  categories,
  categoryMeta,
  helpers,
  pageTransition,
}) => {
  const {
    normalizeProductVariants,
    clampStock,
    isProductOnSale,
    getDiscountPercent,
    colorPresets,
    normalizeHeroConfig,
  } = helpers;

  const [activeCategory, setActiveCategory] = useState('الكل');
  const [sortBy, setSortBy] = useState('newest');
  const [maxPrice, setMaxPrice] = useState(1000);
  const [showPriceFilter, setShowPriceFilter] = useState(false);
  const [activeHeroSlide, setActiveHeroSlide] = useState(0);
  const [variantSelections, setVariantSelections] = useState({});
  const [previewProductId, setPreviewProductId] = useState(null);
  const [previewQty, setPreviewQty] = useState(1);
  const [previewImageIndex, setPreviewImageIndex] = useState(0);

  const isOffersPage = currentRoute === routes.offers;
  const heroConfig = useMemo(() => normalizeHeroConfig(siteConfig?.hero), [normalizeHeroConfig, siteConfig?.hero]);

  const maxProductPrice = useMemo(
    () => products.reduce((max, product) => Math.max(max, Number(product.price) || 0), 0),
    [products],
  );
  const sliderMax = Math.max(maxProductPrice, 1000);

  useEffect(() => {
    setMaxPrice(sliderMax);
  }, [sliderMax]);

  useEffect(() => {
    setActiveHeroSlide(0);
  }, [heroConfig.slides]);

  useEffect(() => {
    if (!heroConfig.autoPlay || heroConfig.slides.length <= 1) return undefined;
    const timer = window.setInterval(() => {
      setActiveHeroSlide((prev) => (prev + 1) % heroConfig.slides.length);
    }, heroConfig.slideIntervalMs);
    return () => window.clearInterval(timer);
  }, [heroConfig.autoPlay, heroConfig.slideIntervalMs, heroConfig.slides.length]);

  useEffect(() => {
    setPreviewImageIndex(0);
  }, [previewProductId]);

  const filteredProducts = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const result = products.filter((product) => {
      const inCategory = activeCategory === 'الكل' || product.category === activeCategory;
      const inSearch = !query || product.name.toLowerCase().includes(query);
      const inPrice = Number(product.price) <= maxPrice;
      const inOffers = !isOffersPage || isProductOnSale(product);
      return inCategory && inSearch && inPrice && inOffers;
    });

    switch (sortBy) {
      case 'price-low':
        return [...result].sort((a, b) => Number(a.price) - Number(b.price));
      case 'price-high':
        return [...result].sort((a, b) => Number(b.price) - Number(a.price));
      case 'discount':
        return [...result].sort((a, b) => getDiscountPercent(b) - getDiscountPercent(a));
      default:
        return [...result].sort((a, b) => Number(b.id) - Number(a.id));
    }
  }, [products, activeCategory, searchQuery, maxPrice, isOffersPage, sortBy, isProductOnSale, getDiscountPercent]);

  const featuredProducts = useMemo(
    () =>
      [...filteredProducts]
        .sort((a, b) => (isProductOnSale(b) ? getDiscountPercent(b) : 0) - (isProductOnSale(a) ? getDiscountPercent(a) : 0))
        .slice(0, 8),
    [filteredProducts, getDiscountPercent, isProductOnSale],
  );

  const spotlightProducts = useMemo(() => filteredProducts.slice(0, 5), [filteredProducts]);
  const heroSpotlightProduct = useMemo(() => featuredProducts[0] || filteredProducts[0] || null, [featuredProducts, filteredProducts]);

  const previewProduct = useMemo(
    () => filteredProducts.find((entry) => entry.id === previewProductId) || products.find((entry) => entry.id === previewProductId) || null,
    [filteredProducts, previewProductId, products],
  );
  const previewImages = useMemo(() => getProductImages(previewProduct), [previewProduct]);
  const previewVariants = useMemo(() => normalizeProductVariants(previewProduct?.variants), [normalizeProductVariants, previewProduct]);
  const previewSelection = variantSelections[previewProduct?.id] || {};
  const previewStock = clampStock(previewProduct?.stock);

  useEffect(() => {
    if (!previewProduct || typeof document === 'undefined') return undefined;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [previewProduct]);

  const setProductSelection = (productId, nextValue) => {
    setVariantSelections((prev) => ({
      ...prev,
      [productId]: {
        ...(prev[productId] || {}),
        ...nextValue,
      },
    }));
  };

  const goToHeroRoute = (route) => {
    if (Object.values(routes).includes(route)) {
      navigateTo(route);
      return;
    }
    navigateTo(routes.home);
  };

  const handleAddProduct = (product, quantity = 1, shouldOpenPreview = true) => {
    const variants = normalizeProductVariants(product.variants);
    const selected = variantSelections[product.id] || {};

    if (variants.enableSizes && !selected.size) {
      if (shouldOpenPreview) setPreviewProductId(product.id);
      showToast('اختر المقاس قبل الإضافة للسلة', 'error');
      return false;
    }

    if (variants.enableColors && !selected.color) {
      if (shouldOpenPreview) setPreviewProductId(product.id);
      showToast('اختر اللون قبل الإضافة للسلة', 'error');
      return false;
    }

    const stock = clampStock(product.stock);
    const finalQty = Math.max(1, Math.min(quantity, stock));

    for (let i = 0; i < finalQty; i += 1) {
      onAddToCart({
        ...product,
        selectedSize: selected.size || '',
        selectedColor: selected.color || '',
      });
    }

    showToast(`تمت إضافة ${finalQty} إلى السلة`, 'success');
    return true;
  };

  const openPreview = (productId) => {
    setPreviewProductId(productId);
    setPreviewQty(1);
    setPreviewImageIndex(0);
  };

  const closePreview = () => {
    setPreviewProductId(null);
    setPreviewQty(1);
    setPreviewImageIndex(0);
  };

  const heroImage = heroConfig.slides?.[activeHeroSlide]?.image || heroConfig.slides?.[0]?.image;

  return (
    <Motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={pageTransition}
      className="pb-24 md:pb-12 max-w-[1380px] mx-auto w-full"
    >
      <div className="px-4 md:px-6 pt-4 md:pt-8 space-y-5">
        <section className="relative overflow-hidden rounded-[2rem] md:rounded-[2.6rem] border border-cyan-200/35 bg-gradient-to-br from-slate-950 via-[#0d1b3a] to-[#08263f] text-white shadow-[0_35px_80px_rgba(8,30,52,0.5)]">
          <img src={heroImage} alt="hero" className="absolute inset-0 h-full w-full object-cover opacity-35" />
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_85%_20%,rgba(56,189,248,0.35),transparent_42%),radial-gradient(circle_at_10%_80%,rgba(16,185,129,0.25),transparent_44%)]" />
          <div className="pointer-events-none absolute -top-10 left-16 h-36 w-36 rounded-full bg-emerald-300/20 blur-3xl animate-float-slow" />
          <div className="pointer-events-none absolute bottom-0 right-8 h-44 w-44 rounded-full bg-cyan-300/25 blur-3xl animate-float-slow-reverse" />

          <div className="relative z-10 grid grid-cols-1 md:grid-cols-[1.25fr_0.9fr] gap-4 p-6 md:p-10">
            <div>
              <span className="inline-flex items-center gap-2 rounded-full border border-white/30 bg-white/10 px-3 py-1.5 text-[11px] md:text-xs font-black tracking-wide">
                <Flame size={14} /> {isOffersPage ? 'لوحة العروض الذكية' : 'Discovery Canvas'}
              </span>
              <h1 className="mt-4 text-3xl md:text-5xl font-black leading-[1.25]">
                {isOffersPage ? 'تخفيضات مركزة حسب اهتماماتك' : heroConfig.title || 'تسوق بواجهة مختلفة كليًا'}
              </h1>
              <p className="mt-3 text-sm md:text-lg text-slate-100/90 font-bold max-w-2xl">
                {heroConfig.description || 'تجربة اكتشاف منتجات تفاعلية بتصميم حديث وسلس على الهاتف والحاسوب.'}
              </p>
              <div className="mt-6 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => goToHeroRoute(heroConfig.primaryButtonRoute)}
                  className="inline-flex items-center gap-2 rounded-2xl bg-white px-5 py-3 text-xs md:text-sm font-black text-slate-900 shadow-xl hover:-translate-y-0.5 transition"
                >
                  {heroConfig.primaryButtonText || 'استكشف المنتجات'} <ChevronRight size={16} className="rotate-180" />
                </button>
                <button
                  type="button"
                  onClick={() => goToHeroRoute(heroConfig.secondaryButtonRoute)}
                  className="inline-flex items-center gap-2 rounded-2xl border border-white/30 bg-white/10 px-5 py-3 text-xs md:text-sm font-black text-white hover:bg-white/20 transition"
                >
                  <BadgePercent size={14} /> {heroConfig.secondaryButtonText || 'العروض'}
                </button>
              </div>
            </div>

            <div className="rounded-3xl border border-white/20 bg-white/10 backdrop-blur p-4 md:p-5">
              <p className="text-xs font-black text-cyan-100">منتج مميز</p>
              {heroSpotlightProduct ? (
                <button
                  type="button"
                  onClick={() => openPreview(heroSpotlightProduct.id)}
                  className="mt-3 w-full rounded-2xl border border-white/20 bg-white/10 p-3 text-right hover:bg-white/20 transition"
                >
                  <div className="flex items-center gap-3">
                    <img
                      src={getPrimaryImage(heroSpotlightProduct)}
                      alt={heroSpotlightProduct.name}
                      className="h-16 w-16 rounded-xl object-cover border border-white/20"
                      loading="lazy"
                      decoding="async"
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-black line-clamp-1">{heroSpotlightProduct.name}</p>
                      <p className="mt-1 text-xs font-bold text-cyan-100">{heroSpotlightProduct.price} د.ج</p>
                      {isProductOnSale(heroSpotlightProduct) && (
                        <p className="text-[11px] font-black text-rose-200">خصم {getDiscountPercent(heroSpotlightProduct)}%</p>
                      )}
                    </div>
                  </div>
                </button>
              ) : (
                <p className="mt-3 rounded-2xl border border-white/20 bg-white/10 px-3 py-2 text-xs font-bold text-cyan-100">أضف منتجات ليظهر هنا عنصر مميز تلقائيًا.</p>
              )}
            </div>
          </div>

          {heroConfig.slides.length > 1 && (
            <div className="relative z-10 px-6 md:px-10 pb-5 flex items-center gap-2">
              {heroConfig.slides.map((slide, index) => (
                <button
                  key={slide.id || index}
                  type="button"
                  onClick={() => setActiveHeroSlide(index)}
                  className={`h-2.5 rounded-full transition-all ${index === activeHeroSlide ? 'w-9 bg-white' : 'w-2.5 bg-white/45'}`}
                />
              ))}
            </div>
          )}
        </section>
        <section className="rounded-[1.8rem] border border-slate-200 bg-white/85 p-4 md:p-5 shadow-[0_12px_30px_rgba(15,23,42,0.07)]">
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_auto] gap-3 items-center">
            <div className="relative">
              <Search size={17} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                placeholder="ابحث بالاسم أو النوع..."
                className="shop-input pr-11"
              />
            </div>

            <div className="flex flex-wrap items-center justify-end gap-2">
              <div className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3">
                <ArrowUpDown size={16} className="text-slate-500" />
                <select
                  value={sortBy}
                  onChange={(event) => setSortBy(event.target.value)}
                  className="bg-transparent text-sm font-black text-slate-700 outline-none"
                >
                  <option value="newest">الأحدث</option>
                  <option value="price-low">السعر الأقل</option>
                  <option value="price-high">السعر الأعلى</option>
                  <option value="discount">الأكثر خصمًا</option>
                </select>
              </div>

              <button
                type="button"
                onClick={() => setShowPriceFilter((prev) => !prev)}
                className={`inline-flex items-center gap-2 rounded-2xl border px-3 py-3 text-xs font-black transition ${showPriceFilter ? 'border-emerald-300 bg-emerald-50 text-emerald-700' : 'border-slate-200 bg-slate-50 text-slate-700'}`}
              >
                <Filter size={16} />
                {showPriceFilter ? 'إخفاء فلتر السعر' : 'إظهار فلتر السعر'}
              </button>
            </div>
          </div>

          {showPriceFilter && (
            <div className="mt-3 inline-flex w-full md:w-auto items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3">
              <Filter size={16} className="text-slate-500" />
              <div className="min-w-[130px]">
                <p className="text-[11px] font-black text-slate-500">السعر الأقصى</p>
                <p className="text-xs font-black text-slate-900">{maxPrice} د.ج</p>
              </div>
              <input
                type="range"
                min={0}
                max={sliderMax}
                step={100}
                value={maxPrice}
                onChange={(event) => setMaxPrice(Number(event.target.value))}
                className="w-full md:w-36 accent-emerald-500"
              />
            </div>
          )}

          <div className="relative mt-4">
            <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-8 bg-gradient-to-l from-white to-transparent md:hidden" />
            <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-8 bg-gradient-to-r from-white to-transparent md:hidden" />
            <div className="flex gap-2 overflow-x-auto no-scrollbar snap-x snap-mandatory pb-1 pr-1">
              {categories.map((category) => {
                const categoryInfo = categoryMeta[category] || categoryMeta['الكل'];
                const Icon = categoryInfo.icon;
                return (
                  <button
                    key={category}
                    type="button"
                    onClick={() => setActiveCategory(category)}
                    className={`snap-start shrink-0 inline-flex items-center gap-2 rounded-full px-4 py-2 text-xs md:text-sm font-black border transition ${
                      activeCategory === category
                        ? `bg-gradient-to-l ${categoryInfo.tone} border-transparent text-white shadow-md`
                        : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300'
                    }`}
                  >
                    <Icon size={14} /> {category}
                  </button>
                );
              })}
            </div>
            <p className="mt-2 text-[11px] font-black text-slate-500 md:hidden">اسحب يمينًا أو يسارًا لعرض كل التصنيفات</p>
          </div>
        </section>

        {featuredProducts.length > 0 && (
          <section>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-lg md:text-xl font-black text-slate-900 inline-flex items-center gap-2">
                <Star size={18} className="text-amber-500" /> Discovery Rails
              </h2>
              <p className="text-xs font-black text-slate-500">سحب أفقي للاستكشاف السريع</p>
            </div>
            <div className="flex gap-3 overflow-x-auto no-scrollbar snap-x snap-mandatory pb-2">
              {featuredProducts.map((product) => {
                const stock = clampStock(product.stock);
                return (
                  <button
                    type="button"
                    key={`rail-${product.id}`}
                    onClick={() => openPreview(product.id)}
                    className="snap-start shrink-0 w-[220px] md:w-[260px] rounded-[1.4rem] border border-slate-200 bg-white shadow-[0_10px_30px_rgba(15,23,42,0.08)] overflow-hidden text-right"
                  >
                    <div className="relative h-[155px]">
                      <img src={getPrimaryImage(product)} alt={product.name} className="h-full w-full object-cover" loading="lazy" decoding="async" />
                      {isProductOnSale(product) && <span className="absolute top-2 right-2 rounded-full bg-rose-500 px-2 py-0.5 text-[10px] font-black text-white">-{getDiscountPercent(product)}%</span>}
                    </div>
                    <div className="p-3">
                      <p className="line-clamp-1 text-sm font-black text-slate-900">{product.name}</p>
                      <div className="mt-2 flex items-center justify-between">
                        <p className="text-sm font-black text-slate-900">{product.price} د.ج</p>
                        <span className="text-[10px] font-black text-slate-500">{stock > 0 ? `متاح ${stock}` : 'نفد'}</span>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          </section>
        )}

        {spotlightProducts.length > 0 && (
          <section>
            <h2 className="text-lg md:text-xl font-black text-slate-900 mb-3">Spotlight Mosaic</h2>
            <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
              {spotlightProducts.map((product, index) => (
                <button
                  key={`spotlight-${product.id}`}
                  type="button"
                  onClick={() => openPreview(product.id)}
                  className={`relative overflow-hidden rounded-[1.6rem] border border-slate-200 bg-white text-right shadow-[0_8px_24px_rgba(15,23,42,0.08)] ${index === 0 ? 'md:col-span-3 md:row-span-2 min-h-[260px]' : 'md:col-span-3 min-h-[124px]'}`}
                >
                  <img src={getPrimaryImage(product)} alt={product.name} className="absolute inset-0 h-full w-full object-cover opacity-85" loading="lazy" />
                  <div className="absolute inset-0 bg-gradient-to-t from-slate-950/80 via-slate-900/20 to-transparent" />
                  <div className="absolute bottom-0 right-0 left-0 p-4">
                    <p className="text-sm md:text-base font-black text-white line-clamp-1">{product.name}</p>
                    <p className="text-xs font-bold text-cyan-100 mt-1">{product.price} د.ج</p>
                  </div>
                </button>
              ))}
            </div>
          </section>
        )}
      </div>

      <div className="px-4 md:px-6 mt-4">
        <div className="flex items-center justify-between mb-3">
          <p className="text-sm font-black text-slate-700">{filteredProducts.length} منتج مطابق</p>
          <p className="text-xs font-black text-slate-500">المفضلة: {favorites.length}</p>
        </div>

        {isLoadingProducts ? (
          <ProductsGridSkeleton count={8} />
        ) : filteredProducts.length === 0 ? (
          <EmptyStateCard title="لا توجد نتائج مطابقة" description="جرّب تعديل الفلاتر أو البحث بكلمات أخرى." />
        ) : (
          <div className="grid grid-cols-2 lg:grid-cols-12 gap-3 md:gap-4">
            <AnimatePresence mode="popLayout">
              {filteredProducts.map((product, index) => {
                const stock = clampStock(product.stock);
                const isFavorite = favorites.includes(product.id);
                const productOnSale = isProductOnSale(product);
                const discountPercent = getDiscountPercent(product);
                const spanClass = index % 7 === 0 ? 'lg:col-span-6' : index % 3 === 0 ? 'lg:col-span-4' : 'lg:col-span-3';

                return (
                  <div key={product.id} className={spanClass}>
                    <DiscoveryCard
                      product={product}
                      stock={stock}
                      isFavorite={isFavorite}
                      onToggleFavorite={() => toggleFavorite(product.id)}
                      onQuickAdd={() => handleAddProduct(product, 1, true)}
                      onOpenPreview={() => openPreview(product.id)}
                      productOnSale={productOnSale}
                      discountPercent={discountPercent}
                    />
                  </div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </div>

      <ProductPreviewSheet
        product={previewProduct}
        isOpen={Boolean(previewProduct)}
        onClose={closePreview}
        variants={previewVariants}
        selection={previewSelection}
        onSelectSize={(size) => setProductSelection(previewProduct.id, { size })}
        onSelectColor={(color) => setProductSelection(previewProduct.id, { color })}
        quantity={previewQty}
        setQuantity={setPreviewQty}
        onAddToCart={() => {
          const success = handleAddProduct(previewProduct, previewQty, false);
          if (success) closePreview();
        }}
        colorPresets={colorPresets}
        discountPercent={previewProduct ? getDiscountPercent(previewProduct) : 0}
        inStock={previewStock}
        previewImages={previewImages}
        currentImageIndex={previewImageIndex}
        setCurrentImageIndex={setPreviewImageIndex}
      />
    </Motion.div>
  );
};

export default StorefrontHome;
