import React, { useMemo, useState } from 'react';
import { AnimatePresence, motion as Motion } from 'framer-motion';
import { Heart, Palette, Plus, Ruler, ShoppingBag } from 'lucide-react';
import { EmptyStateCard } from '../../components/ui/StateBlocks';

const StorefrontFavorites = ({
  products,
  favorites,
  toggleFavorite,
  onAddToCart,
  navigateTo,
  showToast,
  routes,
  helpers,
  pageTransition,
}) => {
  const { normalizeProductVariants, isProductOnSale, colorPresets } = helpers;
  const [variantSelections, setVariantSelections] = useState({});

  const favoriteProducts = useMemo(
    () => products.filter((product) => favorites.includes(product.id)),
    [products, favorites],
  );

  const setProductSelection = (productId, nextValue) => {
    setVariantSelections((prev) => ({
      ...prev,
      [productId]: {
        ...(prev[productId] || {}),
        ...nextValue,
      },
    }));
  };

  const handleAddFavoriteProduct = (product) => {
    const variants = normalizeProductVariants(product.variants);
    const selected = variantSelections[product.id] || {};

    if (variants.enableSizes && !selected.size) {
      showToast('اختر المقاس أولاً قبل الإضافة', 'error');
      return;
    }

    if (variants.enableColors && !selected.color) {
      showToast('اختر اللون أولاً قبل الإضافة', 'error');
      return;
    }

    onAddToCart({
      ...product,
      selectedSize: selected.size || '',
      selectedColor: selected.color || '',
    });
    showToast('تمت الإضافة للسلة', 'success');
  };

  return (
    <Motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={pageTransition}
      className="pb-24 md:pb-12 max-w-7xl mx-auto w-full px-4 md:px-6 pt-4 md:pt-10"
    >
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl md:text-3xl font-black text-slate-900">المفضلة</h2>
        <span className="shop-chip bg-rose-50 border-rose-200 text-rose-700">{favoriteProducts.length} عنصر</span>
      </div>

      {favoriteProducts.length === 0 ? (
        <EmptyStateCard
          title="لا توجد منتجات محفوظة"
          description="احفظ المنتجات التي تعجبك لتعود لها سريعًا."
          actionLabel="العودة للاستكشاف"
          onAction={() => navigateTo(routes.home)}
          icon={ShoppingBag}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 md:gap-5">
          <AnimatePresence>
            {favoriteProducts.map((product) => {
              const variants = normalizeProductVariants(product.variants);
              const selected = variantSelections[product.id] || {};

              return (
                <Motion.article
                  key={product.id}
                  layout
                  initial={{ opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  className="group overflow-hidden rounded-[1.6rem] border border-slate-200 bg-white shadow-[0_14px_35px_rgba(15,23,42,0.1)]"
                >
                  <div className="relative h-56 overflow-hidden bg-slate-100">
                    <img src={product.image} loading="lazy" decoding="async" className="h-full w-full object-cover transition-transform duration-700 group-hover:scale-110" alt={product.name} />
                    <button type="button" onClick={() => toggleFavorite(product.id)} className="absolute top-3 left-3 h-9 w-9 rounded-full bg-white/90 border border-white/70 inline-flex items-center justify-center shadow-sm">
                      <Heart size={16} className="fill-rose-500 text-rose-500" />
                    </button>
                  </div>
                  <div className="p-4 space-y-3">
                    <h3 className="font-black text-slate-900 text-base line-clamp-2">{product.name}</h3>
                    <div>
                      <p className="font-black text-emerald-600">{product.price} د.ج</p>
                      {isProductOnSale(product) && <p className="text-xs text-slate-400 line-through font-bold">{product.oldPrice} د.ج</p>}
                    </div>

                    {variants.enableSizes && (
                      <div>
                        <p className="text-[11px] font-black text-slate-500 mb-1 inline-flex items-center gap-1"><Ruler size={12} /> المقاس</p>
                        <div className="flex flex-wrap gap-1.5">
                          {variants.sizes.map((size) => (
                            <button
                              key={size}
                              onClick={() => setProductSelection(product.id, { size })}
                              className={`px-2 py-1 rounded-md border text-[11px] font-black ${selected.size === size ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200'}`}
                            >
                              {size}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {variants.enableColors && (
                      <div>
                        <p className="text-[11px] font-black text-slate-500 mb-1 inline-flex items-center gap-1"><Palette size={12} /> اللون</p>
                        <div className="flex flex-wrap gap-1.5">
                          {variants.colors.map((colorName) => {
                            const preset = colorPresets.find((entry) => entry.name === colorName);
                            return (
                              <button
                                key={colorName}
                                onClick={() => setProductSelection(product.id, { color: colorName })}
                                className={`px-2 py-1 rounded-md border text-[11px] font-black inline-flex items-center gap-1 ${selected.color === colorName ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200'}`}
                              >
                                <span className="w-3 h-3 rounded-full border border-slate-300" style={{ backgroundColor: preset?.hex || '#e2e8f0' }} />
                                {colorName}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    <button
                      onClick={() => handleAddFavoriteProduct(product)}
                      className="w-full rounded-xl bg-slate-900 text-white py-2.5 text-sm font-black inline-flex justify-center items-center gap-2 hover:bg-emerald-500 transition"
                    >
                      <Plus size={15} /> إضافة للسلة
                    </button>
                  </div>
                </Motion.article>
              );
            })}
          </AnimatePresence>
        </div>
      )}
    </Motion.div>
  );
};

export default StorefrontFavorites;
