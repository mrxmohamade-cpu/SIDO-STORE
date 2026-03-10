import React, { Suspense, lazy, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { motion as Motion, AnimatePresence } from 'framer-motion';
import {
  onAuthStateChanged,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut,
} from 'firebase/auth';
import { auth } from './lib/firebase';
import {
  hasFirebaseConfig,
  loadStoreBundle,
  saveOrdersRemote,
  saveProductsRemote,
  saveSiteConfigRemote,
} from './services/storeService';
import { sendOrderNotification } from './services/orderApi';
import { fetchPublicSecurityStatus, trackClientSecurityEvent } from './services/securityApi';
import { readStorage, writeStorage } from './utils/storage';
import { validateCustomerData, validateStockAvailability } from './utils/checkoutValidation';
import { getWilayaNameByCode } from './utils/algeriaLocations';
import { useAlgeriaLocations } from './hooks/useAlgeriaLocations';
import { useToast } from './hooks/useToast';
import Toast from './components/Toast';
import { AnnouncementBar as StoreAnnouncementBar, BottomNav as StoreBottomNav, DesktopNavbar as StoreDesktopNavbar, FloatingWhatsAppButton as StoreFloatingWhatsAppButton, MobileHeader as StoreMobileHeader, StoreFooter as StoreStoreFooter } from './components/storefront/Navigation';
import { EmptyStateCard, ErrorStateCard, ProductsGridSkeleton } from './components/ui/StateBlocks';
import StorefrontHome from './pages/storefront/StorefrontHome';
import StorefrontFavorites from './pages/storefront/StorefrontFavorites';
import StorefrontCart from './pages/storefront/StorefrontCart';
import StorefrontCheckout from './pages/storefront/StorefrontCheckout';
import StorefrontTrack from './pages/storefront/StorefrontTrack';
import CustomerNoticeCenter from './components/storefront/CustomerNoticeCenter';
import {
  AlertTriangle,
  ArrowUpDown,
  BadgePercent,
  CheckCircle,
  ChevronRight,
  CreditCard,
  Edit3,
  Filter,
  Heart,
  Home,
  LayoutDashboard,
  Lock,
  LogOut,
  Mail,
  MessageCircle,
  Megaphone,
  MoonStar,
  Palette,
  Package,
  Plus,
  Power,
  Ruler,
  Search,
  Settings,
  ShieldCheck,
  ShoppingBag,
  ShoppingCart,
  Sparkles,
  Store,
  SunMedium,
  Trash2,
  User,
  XCircle,
} from 'lucide-react';

const CATEGORIES = ['الكل', 'رجال', 'نساء', 'أحذية', 'إكسسوارات'];
const ROUTES = {
  home: 'home',
  offers: 'offers',
  favorites: 'favorites',
  cart: 'cart',
  checkout: 'checkout',
  track: 'track',
  admin: 'admin',
};

const PAGE_TRANSITION = { duration: 0.35, ease: 'easeOut' };

const CATEGORY_META = {
  الكل: { icon: LayoutDashboard, tone: 'from-slate-600 to-slate-800' },
  رجال: { icon: User, tone: 'from-blue-500 to-indigo-600' },
  نساء: { icon: Heart, tone: 'from-rose-500 to-pink-600' },
  أحذية: { icon: ShoppingBag, tone: 'from-amber-500 to-orange-600' },
  إكسسوارات: { icon: Sparkles, tone: 'from-emerald-500 to-teal-600' },
};

const DEFAULT_PRODUCT_CATEGORIES = ['\u0631\u062c\u0627\u0644', '\u0646\u0633\u0627\u0621', '\u0623\u062d\u0630\u064a\u0629', '\u0625\u0643\u0633\u0633\u0648\u0627\u0631\u0627\u062a', '\u0623\u062e\u0631\u0649'];

const ORDER_STATUSES = [
  { key: 'pending', label: '\u062a\u0645 \u0627\u0633\u062a\u0644\u0627\u0645 \u0627\u0644\u0637\u0644\u0628', className: 'bg-amber-100 text-amber-700 border-amber-200' },
  { key: 'confirmed', label: '\u062a\u0645 \u0627\u0644\u062a\u0623\u0643\u064a\u062f', className: 'bg-cyan-100 text-cyan-700 border-cyan-200' },
  { key: 'processing', label: '\u0642\u064a\u062f \u0627\u0644\u0645\u0639\u0627\u0644\u062c\u0629', className: 'bg-indigo-100 text-indigo-700 border-indigo-200' },
  { key: 'shipped', label: '\u062a\u0645 \u0627\u0644\u0634\u062d\u0646', className: 'bg-blue-100 text-blue-700 border-blue-200' },
  { key: 'out_for_delivery', label: '\u0641\u064a \u0627\u0644\u062a\u0648\u0635\u064a\u0644', className: 'bg-violet-100 text-violet-700 border-violet-200' },
  { key: 'delivered', label: '\u062a\u0645 \u0627\u0644\u062a\u0633\u0644\u064a\u0645', className: 'bg-emerald-100 text-emerald-700 border-emerald-200' },
  { key: 'cancelled', label: '\u0645\u0644\u063a\u064a', className: 'bg-rose-100 text-rose-700 border-rose-200' },
];

const STORAGE_KEYS = {
  products: 'my_store_products_v2',
  orders: 'my_store_orders_v2',
  customerOrders: 'my_store_customer_orders_v1',
  cart: 'my_store_cart_v1',
  siteConfig: 'my_store_site_config_v2',
  favorites: 'my_store_favorites_v1',
  adminTheme: 'my_store_admin_theme_v1',
};

const DEFAULT_HERO_CONFIG = {
  title: 'تسوق أحدث المنتجات بسهولة',
  description: 'منتجات مختارة بعناية مع جودة عالية والدفع عند الاستلام.',
  primaryButtonText: 'تصفح المنتجات',
  primaryButtonRoute: ROUTES.home,
  secondaryButtonText: 'العروض',
  secondaryButtonRoute: ROUTES.offers,
  enableAnimation: true,
  autoPlay: true,
  slideIntervalMs: 4800,
  slides: [
    {
      id: 'hero-1',
      image: 'https://images.unsplash.com/photo-1523381210434-271e8be1f52b?auto=format&fit=crop&w=1600&q=80',
      alt: 'منتجات حديثة',
    },
    {
      id: 'hero-2',
      image: 'https://images.unsplash.com/photo-1512436991641-6745cdb1723f?auto=format&fit=crop&w=1600&q=80',
      alt: 'تجربة تسوق',
    },
  ],
};

const DEFAULT_SITE_CONFIG = {
  name: 'أناقة ستور',
  isOnline: true,
  announcement: '',
  hero: DEFAULT_HERO_CONFIG,
  productCategories: [...DEFAULT_PRODUCT_CATEGORIES],
  customerNotices: [],
  showCouponInput: false,
  couponCode: '',
  couponDiscount: 0,
  coupons: [],
  whatsappNumber: '',
  facebookUrl: '',
  instagramUrl: '',
  logoUrl: '',
  shippingFeesByWilaya: {},
};

const CLOTHING_SIZES = ['S', 'M', 'L', 'XL', 'XXL'];
const SHOE_SIZES = Array.from({ length: 9 }, (_, idx) => String(37 + idx));
const COLOR_PRESETS = [
  { name: 'أسود', hex: '#111827' },
  { name: 'أبيض', hex: '#F8FAFC' },
  { name: 'رمادي', hex: '#9CA3AF' },
  { name: 'أزرق', hex: '#2563EB' },
  { name: 'كحلي', hex: '#1E3A8A' },
  { name: 'أخضر', hex: '#059669' },
  { name: 'أحمر', hex: '#DC2626' },
  { name: 'وردي', hex: '#EC4899' },
  { name: 'بيج', hex: '#D6C6A5' },
  { name: 'بني', hex: '#92400E' },
];

const DEFAULT_PRODUCT_VARIANTS = {
  enableSizes: false,
  sizeType: 'clothing',
  sizes: [],
  enableColors: false,
  colors: [],
};

const initialProductsData = [
  {
    id: 1,
    name: 'تيشيرت صيفي قطن',
    price: 2500,
    oldPrice: 3200,
    category: 'رجال',
    stock: 12,
    image: 'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=800&q=80',
    variants: {
      ...DEFAULT_PRODUCT_VARIANTS,
      enableSizes: true,
      sizeType: 'clothing',
      sizes: ['M', 'L', 'XL'],
      enableColors: true,
      colors: ['أسود', 'أبيض', 'أزرق'],
    },
  },
  { id: 2, name: 'فستان كاجوال مريح', price: 4800, category: 'نساء', stock: 8, image: 'https://images.unsplash.com/photo-1515347619362-ec8cb9eb7a7a?auto=format&fit=crop&w=800&q=80' },
  {
    id: 3,
    name: 'حذاء رياضي يومي',
    price: 5500,
    oldPrice: 6900,
    category: 'أحذية',
    stock: 5,
    image: 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=800&q=80',
    variants: {
      ...DEFAULT_PRODUCT_VARIANTS,
      enableSizes: true,
      sizeType: 'shoes',
      sizes: ['40', '41', '42', '43', '44'],
      enableColors: true,
      colors: ['أسود', 'أبيض', 'رمادي'],
    },
  },
  { id: 4, name: 'ساعة يد كلاسيكية', price: 3200, category: 'إكسسوارات', stock: 15, image: 'https://images.unsplash.com/photo-1524592094714-0f0654e20314?auto=format&fit=crop&w=800&q=80' },
];
const clampStock = (value) => Math.max(0, Number(value) || 0);
const clampDiscount = (value) => Math.min(90, Math.max(0, Number(value) || 0));
const normalizeCouponCode = (value) =>
  String(value || '')
    .trim()
    .toUpperCase()
    .replace(/\s+/g, '');
const clampUses = (value) => Math.max(1, Number(value) || 1);

const normalizeProductVariants = (variants) => {
  const source = variants || {};
  const sizeType = source.sizeType === 'shoes' ? 'shoes' : 'clothing';
  const allowedSizes = sizeType === 'shoes' ? SHOE_SIZES : CLOTHING_SIZES;
  const uniqueSizes = Array.from(
    new Set((Array.isArray(source.sizes) ? source.sizes : []).map((entry) => String(entry).trim())),
  ).filter((entry) => allowedSizes.includes(entry));
  const uniqueColors = Array.from(
    new Set((Array.isArray(source.colors) ? source.colors : []).map((entry) => String(entry).trim())),
  ).filter(Boolean);

  return {
    enableSizes: Boolean(source.enableSizes) && uniqueSizes.length > 0,
    sizeType,
    sizes: uniqueSizes,
    enableColors: Boolean(source.enableColors) && uniqueColors.length > 0,
    colors: uniqueColors,
  };
};

const buildCartItemKey = (item) =>
  String(item?.id || 'no-id') + '::' + (item?.selectedSize || 'no-size') + '::' + (item?.selectedColor || 'no-color');

const isProductOnSale = (product) =>
  Number(product.oldPrice) > 0 && Number(product.oldPrice) > Number(product.price);

const getDiscountPercent = (product) => {
  if (!isProductOnSale(product)) return 0;
  return Math.round(((Number(product.oldPrice) - Number(product.price)) / Number(product.oldPrice)) * 100);
};

const normalizeCoupons = (coupons, legacyCode, legacyDiscount) => {
  const source = Array.isArray(coupons) ? coupons : [];
  const normalized = source
    .map((coupon, index) => {
      const code = normalizeCouponCode(coupon?.code);
      if (!code) return null;

      const expiresAt = coupon?.expiresAt ? new Date(coupon.expiresAt).toISOString() : '';
      return {
        id: coupon?.id || String(Date.now()) + '-' + String(index) + '-' + code,
        code,
        discount: clampDiscount(coupon?.discount),
        maxUses: clampUses(coupon?.maxUses),
        usedCount: Math.max(0, Number(coupon?.usedCount) || 0),
        expiresAt,
      };
    })
    .filter(Boolean)
    .filter((coupon) => coupon.discount > 0);

  if (normalized.length > 0) return normalized;

  const fallbackCode = normalizeCouponCode(legacyCode);
  const fallbackDiscount = clampDiscount(legacyDiscount);
  if (!fallbackCode || fallbackDiscount <= 0) return [];

  return [
    {
      id: 'legacy-' + fallbackCode,
      code: fallbackCode,
      discount: fallbackDiscount,
      maxUses: 99999,
      usedCount: 0,
      expiresAt: '',
    },
  ];
};

const normalizeHeroSlides = (slides) => {
  const source = Array.isArray(slides) ? slides : [];
  const normalized = source
    .map((slide, index) => {
      const image = String(slide?.image || '').trim();
      if (!image) return null;

      return {
        id: String(slide?.id || `hero-${Date.now()}-${index}`),
        image,
        alt: String(slide?.alt || '').trim(),
      };
    })
    .filter(Boolean);

  return normalized.length > 0
    ? normalized
    : DEFAULT_HERO_CONFIG.slides.map((slide) => ({ ...slide }));
};

const normalizeHeroConfig = (hero) => {
  const merged = {
    ...DEFAULT_HERO_CONFIG,
    ...(hero || {}),
  };

  const allowedRoutes = new Set(Object.values(ROUTES));
  const primaryRoute = allowedRoutes.has(merged.primaryButtonRoute) ? merged.primaryButtonRoute : ROUTES.home;
  const secondaryRoute = allowedRoutes.has(merged.secondaryButtonRoute) ? merged.secondaryButtonRoute : ROUTES.offers;

  return {
    ...merged,
    title: String(merged.title || '').trim() || DEFAULT_HERO_CONFIG.title,
    description: String(merged.description || '').trim() || DEFAULT_HERO_CONFIG.description,
    primaryButtonText: String(merged.primaryButtonText || '').trim() || DEFAULT_HERO_CONFIG.primaryButtonText,
    secondaryButtonText: String(merged.secondaryButtonText || '').trim() || DEFAULT_HERO_CONFIG.secondaryButtonText,
    primaryButtonRoute: primaryRoute,
    secondaryButtonRoute: secondaryRoute,
    enableAnimation: Boolean(merged.enableAnimation),
    autoPlay: Boolean(merged.autoPlay),
    slideIntervalMs: Math.min(12000, Math.max(2500, Number(merged.slideIntervalMs) || DEFAULT_HERO_CONFIG.slideIntervalMs)),
    slides: normalizeHeroSlides(merged.slides),
  };
};

const NOTICE_LEVELS = new Set(['normal', 'important', 'critical']);

const normalizeProductCategories = (categories) => {
  const source = Array.isArray(categories) ? categories : [];
  const normalized = Array.from(
    new Set(
      source
        .map((entry) => String(entry || '').trim())
        .filter((entry) => entry && entry !== '\u0627\u0644\u0643\u0644'),
    ),
  );

  const fallback = normalized.length > 0 ? normalized : [...DEFAULT_PRODUCT_CATEGORIES];
  if (!fallback.includes('\u0623\u062e\u0631\u0649')) fallback.push('\u0623\u062e\u0631\u0649');
  return fallback;
};

const normalizeCustomerNotices = (notices) => {
  const source = Array.isArray(notices) ? notices : [];

  return source
    .map((notice, index) => {
      const title = String(notice?.title || '').trim();
      const message = String(notice?.message || '').trim();
      if (!title && !message) return null;

      const level = NOTICE_LEVELS.has(String(notice?.level || '')) ? String(notice.level) : 'normal';
      const startAt = notice?.startAt ? new Date(notice.startAt).toISOString() : '';
      const endAt = notice?.endAt ? new Date(notice.endAt).toISOString() : '';

      return {
        id: String(notice?.id || ('notice-' + Date.now() + '-' + index)),
        title,
        message,
        level,
        image: String(notice?.image || '').trim(),
        enabled: Boolean(notice?.enabled ?? true),
        startAt,
        endAt,
        priority: Number(notice?.priority) || 0,
        createdAt: notice?.createdAt ? new Date(notice.createdAt).toISOString() : new Date().toISOString(),
        updatedAt: notice?.updatedAt ? new Date(notice.updatedAt).toISOString() : new Date().toISOString(),
      };
    })
    .filter(Boolean)
    .sort((a, b) => Number(b.priority || 0) - Number(a.priority || 0));
};

const normalizeShippingFeesByWilaya = (value) => {
  if (!value || typeof value !== 'object') return {};

  return Object.entries(value).reduce((acc, [rawCode, rawFee]) => {
    const wilayaCode = String(rawCode || '').trim().padStart(2, '0');
    if (!wilayaCode) return acc;
    const fee = Math.max(0, Number(rawFee) || 0);
    acc[wilayaCode] = fee;
    return acc;
  }, {});
};

const normalizeSiteConfig = (siteConfig) => {
  const merged = {
    ...DEFAULT_SITE_CONFIG,
    ...(siteConfig || {}),
  };

  return {
    ...merged,
    hero: normalizeHeroConfig(merged.hero),
    isOnline: Boolean(merged.isOnline),
    showCouponInput: Boolean(merged.showCouponInput),
    announcement: String(merged.announcement || ''),
    whatsappNumber: String(merged.whatsappNumber || ''),
    facebookUrl: String(merged.facebookUrl || '').trim(),
    instagramUrl: String(merged.instagramUrl || '').trim(),
    logoUrl: String(merged.logoUrl || '').trim(),
    shippingFeesByWilaya: normalizeShippingFeesByWilaya(merged.shippingFeesByWilaya),
    coupons: normalizeCoupons(merged.coupons, merged.couponCode, merged.couponDiscount),
    productCategories: normalizeProductCategories(merged.productCategories),
    customerNotices: normalizeCustomerNotices(merged.customerNotices),
  };
};

const isCouponExpired = (coupon) => Boolean(coupon?.expiresAt) && new Date(coupon.expiresAt).getTime() < Date.now();

const isCouponExhausted = (coupon) => (Number(coupon?.usedCount) || 0) >= (Number(coupon?.maxUses) || 0);

const isCouponApplicable = (coupon) =>
  Boolean(coupon?.code) &&
  Number(coupon?.discount) > 0 &&
  !isCouponExpired(coupon) &&
  !isCouponExhausted(coupon);

const normalizeProducts = (items) => {
  if (!Array.isArray(items)) return initialProductsData;

  return items.map((item, index) => {
    const rawImages = Array.isArray(item.images) ? item.images : [];
    const normalizedImages = Array.from(
      new Set(
        [
          ...rawImages.map((entry) => String(entry || '').trim()),
          String(item.image || '').trim(),
        ].filter(Boolean),
      ),
    );

    const coverImage = normalizedImages[0] || String(item.image || '').trim();

    return {
      ...item,
      id: item.id ?? Date.now() + index,
      name: String(item.name || '').trim(),
      description: String(item.description || '').trim(),
      category: String(item.category || '\u0623\u062e\u0631\u0649').trim() || '\u0623\u062e\u0631\u0649',
      image: coverImage,
      images: normalizedImages.length > 0 ? normalizedImages : (coverImage ? [coverImage] : []),
      price: Number(item.price) || 0,
      oldPrice: Number(item.oldPrice) > 0 ? Number(item.oldPrice) : 0,
      stock: clampStock(item.stock ?? 0),
      variants: normalizeProductVariants(item.variants),
    };
  });
};

const normalizeOrders = (items) => {
  if (!Array.isArray(items)) return [];
  return items.map((item, index) => ({
    ...item,
    id: item.id ?? Date.now() + index,
    items: Array.isArray(item.items)
      ? item.items.map((orderItem) => ({
          ...orderItem,
          cartKey: orderItem.cartKey || buildCartItemKey(orderItem),
        }))
      : [],
    subtotal: Number(item.subtotal) || Number(item.totalPrice) || 0,
    discount: Number(item.discount) || 0,
    totalPrice: Number(item.totalPrice) || 0,
    couponCode: item.couponCode || '',
    status: item.status || 'pending',
    date: item.date || new Date().toISOString(),
  }));
};

const normalizeCartItems = (items) => {
  if (!Array.isArray(items)) return [];

  return items
    .map((item, index) => {
      const rawImages = Array.isArray(item?.images) ? item.images : [];
      const normalizedImages = Array.from(
        new Set(
          [
            ...rawImages.map((entry) => String(entry || '').trim()),
            String(item?.image || '').trim(),
          ].filter(Boolean),
        ),
      );
      const coverImage = normalizedImages[0] || String(item?.image || '').trim();
      const stock = item?.stock === undefined || item?.stock === null || item?.stock === ''
        ? Number.POSITIVE_INFINITY
        : clampStock(item.stock);

      return {
        ...item,
        id: item?.id ?? ('cart-item-' + index),
        name: String(item?.name || '').trim(),
        image: coverImage,
        images: normalizedImages,
        price: Math.max(0, Number(item?.price) || 0),
        oldPrice: Number(item?.oldPrice) > 0 ? Number(item.oldPrice) : 0,
        stock,
        qty: Math.max(1, Number(item?.qty) || 1),
        selectedSize: String(item?.selectedSize || '').trim(),
        selectedColor: String(item?.selectedColor || '').trim(),
        cartKey: item?.cartKey || buildCartItemKey(item || {}),
        variants: normalizeProductVariants(item?.variants),
      };
    })
    .filter((item) => item.name || item.id);
};

const mergeCustomerOrdersWithOrders = (currentCustomerOrders, allOrders) => {
  const customerList = Array.isArray(currentCustomerOrders) ? currentCustomerOrders : [];
  const liveOrders = Array.isArray(allOrders) ? allOrders : [];
  if (customerList.length === 0 || liveOrders.length === 0) return customerList;

  const ordersMap = new Map(liveOrders.map((entry) => [String(entry.id), entry]));
  let changed = false;

  const nextOrders = customerList.map((entry) => {
    const liveOrder = ordersMap.get(String(entry.id));
    if (!liveOrder) return entry;

    const mergedOrder = {
      ...entry,
      ...liveOrder,
      customer: {
        ...(entry.customer || {}),
        ...(liveOrder.customer || {}),
      },
      items: Array.isArray(liveOrder.items) && liveOrder.items.length > 0 ? liveOrder.items : entry.items,
    };

    if (JSON.stringify(mergedOrder) !== JSON.stringify(entry)) {
      changed = true;
    }

    return mergedOrder;
  });

  return changed ? normalizeOrders(nextOrders) : customerList;
};

const getOrderStatusMeta = (status) => {
  const found = ORDER_STATUSES.find((entry) => entry.key === status);
  return found || ORDER_STATUSES[0];
};

const cartReducer = (state, action) => {
  switch (action.type) {
    case 'ADD_ITEM': {
      const stock = Number.isFinite(Number(action.payload.stock))
        ? Number(action.payload.stock)
        : Number.POSITIVE_INFINITY;
      const qtyToAdd = Math.max(1, Number(action.payload.qtyToAdd) || 1);

      if (stock <= 0) return state;

      const incomingKey = action.payload.cartKey || buildCartItemKey(action.payload);
      const existing = state.find((item) => (item.cartKey || buildCartItemKey(item)) === incomingKey);
      if (existing) {
        if (existing.qty >= stock) return state;
        const allowedQty = Math.min(qtyToAdd, stock - existing.qty);
        if (allowedQty <= 0) return state;
        return state.map((item) =>
          (item.cartKey || buildCartItemKey(item)) === incomingKey ? { ...item, qty: item.qty + allowedQty } : item,
        );
      }

      const initialQty = Math.min(qtyToAdd, stock);
      const { qtyToAdd: _qtyToAdd, ...payload } = action.payload;
      return [...state, { ...payload, cartKey: incomingKey, qty: initialQty }];
    }
    case 'REMOVE_ITEM': {
      const targetKey = action.payload?.cartKey || buildCartItemKey(action.payload || {});
      return state.filter((item) => (item.cartKey || buildCartItemKey(item)) !== targetKey);
    }
    case 'DECREASE': {
      const targetKey = action.payload?.cartKey || buildCartItemKey(action.payload || {});
      return state.map((item) =>
        (item.cartKey || buildCartItemKey(item)) === targetKey && item.qty > 1 ? { ...item, qty: item.qty - 1 } : item,
      );
    }
    case 'CLEAR':
      return [];
    default:
      return state;
  }
};
const AnnouncementBar = (props) => <StoreAnnouncementBar {...props} />;

const FloatingWhatsAppButton = ({ phoneNumber, facebookUrl, instagramUrl }) => (
  <StoreFloatingWhatsAppButton
    phoneNumber={phoneNumber}
    facebookUrl={facebookUrl}
    instagramUrl={instagramUrl}
    transition={PAGE_TRANSITION}
  />
);

const DesktopNavbar = (props) => <StoreDesktopNavbar {...props} routes={ROUTES} />;

const MobileHeader = (props) => <StoreMobileHeader {...props} routes={ROUTES} />;

const BottomNav = (props) => <StoreBottomNav {...props} routes={ROUTES} />;

const StoreFooter = (props) => <StoreStoreFooter {...props} routes={ROUTES} />;

const MaintenanceView = ({ siteName, onOpenAdmin }) => (
  <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-900/80 flex flex-col items-center justify-center p-4 text-center text-white">
    <Motion.div
      initial={{ scale: 0.95, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={PAGE_TRANSITION}
      className="relative overflow-hidden bg-white/10 backdrop-blur-2xl p-8 md:p-10 rounded-[2.5rem] shadow-2xl border border-white/20 max-w-xl w-full"
    >
      <div className="absolute -top-20 -left-10 w-48 h-48 rounded-full bg-emerald-400/20 blur-3xl" />
      <div className="absolute -bottom-20 -right-10 w-48 h-48 rounded-full bg-cyan-400/20 blur-3xl" />

      <div className="relative z-10">
        <div className="w-24 h-24 bg-orange-400/20 text-orange-300 rounded-full flex items-center justify-center mx-auto mb-6 border border-orange-200/30">
          <Power size={42} />
        </div>
        <h2 className="text-3xl md:text-4xl font-black mb-4">{siteName}</h2>
        <p className="text-base md:text-lg font-bold text-slate-200 mb-8">المتجر الآن في وضع الصيانة لتحسين الأداء وتجربة التسوق. سنعود خلال وقت قصير.</p>

        <div className="flex items-center justify-center gap-2 text-sm text-slate-100 font-bold bg-white/10 py-3 px-6 rounded-full w-fit mx-auto border border-white/20 mb-6">
          <ShieldCheck size={16} /> تحديثات جارية بشكل آمن
        </div>

        <button
          onClick={onOpenAdmin}
          className="inline-flex items-center gap-2 bg-white text-slate-900 px-6 py-3 rounded-full font-black hover:bg-slate-100 transition"
        >
          <Lock size={18} /> دخول الإدارة
        </button>
      </div>
    </Motion.div>
  </div>
);

const BlockedAccessView = ({ siteName, blockedUntil, blockedReason, onRefresh }) => {
  const blockedUntilLabel = blockedUntil
    ? new Date(blockedUntil).toLocaleString('ar-DZ')
    : '';

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-rose-950/80 flex flex-col items-center justify-center p-4 text-center text-white">
      <Motion.div
        initial={{ scale: 0.96, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={PAGE_TRANSITION}
        className="relative overflow-hidden bg-white/10 backdrop-blur-2xl p-8 md:p-10 rounded-[2.5rem] shadow-2xl border border-white/20 max-w-xl w-full"
      >
        <div className="absolute -top-16 -left-8 h-40 w-40 rounded-full bg-rose-400/20 blur-3xl" />
        <div className="absolute -bottom-16 -right-8 h-40 w-40 rounded-full bg-amber-300/20 blur-3xl" />

        <div className="relative z-10">
          <div className="mx-auto mb-6 flex h-24 w-24 items-center justify-center rounded-full border border-rose-200/30 bg-rose-400/15 text-rose-200">
            <ShieldCheck size={42} />
          </div>
          <h2 className="text-3xl md:text-4xl font-black mb-3">تم تقييد الوصول مؤقتًا</h2>
          <p className="text-base md:text-lg font-bold text-slate-200 mb-3">رصد نظام الحماية نشاطًا غير طبيعي من هذا الجهاز، لذلك تم إيقاف الوصول مؤقتًا إلى {siteName || 'المتجر'}.</p>
          <div className="space-y-2 rounded-3xl border border-white/15 bg-white/10 px-5 py-4 text-sm font-bold text-slate-100">
            <p>{blockedUntilLabel ? 'يمكنك المحاولة مجددًا بعد ' + blockedUntilLabel : 'يمكنك المحاولة لاحقًا أو انتظار مراجعة المسؤول.'}</p>
            {blockedReason ? <p className="text-rose-100/90">السبب: {blockedReason}</p> : null}
          </div>

          <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
            <button
              type="button"
              onClick={onRefresh}
              className="inline-flex items-center gap-2 rounded-full bg-white px-6 py-3 font-black text-slate-900 transition hover:bg-slate-100"
            >
              <RefreshCw size={18} /> تحديث الحالة
            </button>
            <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-5 py-3 text-sm font-bold text-slate-100">
              <AlertTriangle size={16} /> إذا كنت المالك، افتح لوحة الإدارة من جهاز أو عنوان IP غير محظور لفك الحظر.
            </span>
          </div>
        </div>
      </Motion.div>
    </div>
  );
};
const OrderStatusPill = ({ status }) => {
  const meta = getOrderStatusMeta(status);
  return <span className={`text-xs font-black px-3 py-1 rounded-full border ${meta.className}`}>{meta.label}</span>;
};
const HomeView = ({
  products,
  onAddToCart,
  showToast,
  searchQuery,
  setSearchQuery,
  favorites,
  toggleFavorite,
  orders,
  isLoadingProducts,
  currentRoute,
  navigateTo,
  siteConfig,
}) => {
  const [activeCategory, setActiveCategory] = useState('الكل');
  const [sortBy, setSortBy] = useState('newest');
  const [variantSelections, setVariantSelections] = useState({});
  const [activeHeroSlide, setActiveHeroSlide] = useState(0);

  const isOffersPage = currentRoute === ROUTES.offers;
  const heroConfig = useMemo(() => normalizeHeroConfig(siteConfig?.hero), [siteConfig?.hero]);

  const maxProductPrice = useMemo(
    () => products.reduce((max, product) => Math.max(max, Number(product.price) || 0), 0),
    [products],
  );
  const sliderMax = Math.max(maxProductPrice, 1000);
  const [maxPrice, setMaxPrice] = useState(sliderMax);

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
        return [...result].sort((a, b) => a.price - b.price);
      case 'price-high':
        return [...result].sort((a, b) => b.price - a.price);
      case 'discount':
        return [...result].sort((a, b) => getDiscountPercent(b) - getDiscountPercent(a));
      default:
        return [...result].sort((a, b) => Number(b.id) - Number(a.id));
    }
  }, [products, activeCategory, searchQuery, maxPrice, sortBy, isOffersPage]);

  const recentOrders = useMemo(() => orders.slice(0, 3), [orders]);

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
    if (Object.values(ROUTES).includes(route)) {
      navigateTo(route);
      return;
    }
    navigateTo(ROUTES.home);
  };

  const handleAddProduct = (product) => {
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
    <Motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={PAGE_TRANSITION} className="pb-24 md:pb-10 max-w-7xl mx-auto w-full">
      <div className="px-4 py-4 md:py-8">
        <div className="bg-slate-900 rounded-[2rem] p-8 md:p-16 text-white relative overflow-hidden shadow-2xl flex flex-col justify-center min-h-[200px] md:min-h-[360px]">
          <div className="relative z-10 max-w-2xl">
            <span className="bg-emerald-500 text-white text-xs md:text-sm font-bold px-3 py-1.5 rounded-full uppercase tracking-wider mb-4 inline-block shadow-lg shadow-emerald-500/30">
              {isOffersPage ? 'خصومات مباشرة' : 'توصيل لـ 58 ولاية'}
            </span>
            <h2 className="text-3xl md:text-6xl font-black mb-4 leading-tight">
              {isOffersPage ? '\u0623\u0641\u0636\u0644 \u0627\u0644\u0639\u0631\u0648\u0636' : heroConfig.title || '\u0623\u062d\u062f\u062b \u0635\u064a\u062d\u0627\u062a'}
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-l from-emerald-300 to-teal-200">
                {isOffersPage ? '\u062a\u062e\u0641\u064a\u0636\u0627\u062a \u0627\u0644\u064a\u0648\u0645' : heroConfig.secondaryButtonText || '\u0627\u0644\u0645\u0648\u0636\u0629 \u0628\u064a\u0646 \u064a\u062f\u064a\u0643'}
              </span>
            </h2>
            <p className="text-slate-300 text-sm md:text-xl font-medium">{heroConfig.description || '\u062a\u0633\u0648\u0642 \u0627\u0644\u0622\u0646 \u0648\u0627\u062f\u0641\u0639 \u0639\u0646\u062f \u0627\u0644\u0627\u0633\u062a\u0644\u0627\u0645 \u0628\u0643\u0644 \u0623\u0645\u0627\u0646 \u0648\u0633\u0647\u0648\u0644\u0629.'}</p>
            <div className="mt-4 flex gap-2">
              <button
                onClick={() => goToHeroRoute(heroConfig.primaryButtonRoute)}
                className={`px-4 py-2 rounded-full text-xs font-black border ${!isOffersPage ? 'bg-white text-slate-900 border-white' : 'bg-white/10 text-white border-white/20'}`}
              >
                {heroConfig.primaryButtonText || '\u0643\u0644 \u0627\u0644\u0645\u0646\u062a\u062c\u0627\u062a'}
              </button>
              <button
                onClick={() => goToHeroRoute(heroConfig.secondaryButtonRoute)}
                className={`px-4 py-2 rounded-full text-xs font-black border inline-flex items-center gap-1 ${isOffersPage ? 'bg-rose-500 text-white border-rose-500' : 'bg-white/10 text-white border-white/20'}`}
              >
                <BadgePercent size={14} /> {heroConfig.secondaryButtonText || '\u0627\u0644\u0639\u0631\u0648\u0636'}
              </button>
            </div>
          </div>
          <img
            src={heroConfig.slides?.[activeHeroSlide]?.image || heroConfig.slides?.[0]?.image || 'https://images.unsplash.com/photo-1441984904996-e0b6ba687e04?auto=format&fit=crop&w=1200&q=80'}
            className="absolute left-0 top-0 w-2/3 md:w-1/2 h-full object-cover opacity-40 mix-blend-luminosity transition-all duration-700"
            alt="Banner"
          />

          {heroConfig.slides.length > 1 && (
            <div className="absolute bottom-4 left-4 right-4 z-20 flex items-center justify-between">
              <div className="flex gap-1.5 bg-black/35 backdrop-blur rounded-full px-2 py-1">
                {heroConfig.slides.map((slide, index) => (
                  <button
                    key={slide.id || String(index)}
                    type="button"
                    onClick={() => setActiveHeroSlide(index)}
                    className={`h-2.5 rounded-full transition-all ${activeHeroSlide === index ? 'w-6 bg-white' : 'w-2.5 bg-white/45'}`}
                  />
                ))}
              </div>

              <div className="hidden md:flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setActiveHeroSlide((prev) => (prev - 1 + heroConfig.slides.length) % heroConfig.slides.length)}
                  className="w-8 h-8 rounded-full bg-black/35 border border-white/20 text-white inline-flex items-center justify-center"
                >
                  <ChevronRight size={14} />
                </button>
                <button
                  type="button"
                  onClick={() => setActiveHeroSlide((prev) => (prev + 1) % heroConfig.slides.length)}
                  className="w-8 h-8 rounded-full bg-black/35 border border-white/20 text-white inline-flex items-center justify-center"
                >
                  <ChevronRight size={14} className="rotate-180" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {recentOrders.length > 0 && !isOffersPage && (
        <div className="px-4 mb-6">
          <div className="bg-white border border-gray-100 rounded-3xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-black text-slate-900">آخر طلباتك</h3>
              <span className="text-xs font-bold text-gray-500">{orders.length} طلب</span>
            </div>
            <div className="space-y-3">
              {recentOrders.map((order) => (
                <div key={order.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-2xl border border-gray-100">
                  <div>
                    <p className="font-black text-slate-900">طلب #{String(order.id).slice(-5)}</p>
                    <p className="text-xs text-gray-500 font-bold">{new Date(order.date).toLocaleDateString('ar-DZ')}</p>
                  </div>
                  <OrderStatusPill status={order.status} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="px-4 md:hidden mb-4">
        <div className="relative">
          <Search className="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
          <input
            type="text"
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="ابحث عن المنتجات..."
            className="w-full bg-white border border-gray-200 rounded-2xl py-3 pr-11 pl-4 outline-none focus:ring-2 focus:ring-emerald-500 text-sm font-bold"
          />
        </div>
      </div>

      <div className="px-4 py-2 overflow-x-auto no-scrollbar flex gap-2 md:gap-4 md:justify-center md:mb-6 md:mt-2">
        {CATEGORIES.map((category) => {
          const categoryMeta = CATEGORY_META[category] || CATEGORY_META['الكل'];
          const CategoryIcon = categoryMeta.icon;

          return (
            <button
              key={category}
              onClick={() => setActiveCategory(category)}
              className={`whitespace-nowrap px-4 py-2.5 rounded-full text-sm font-bold transition-all duration-300 inline-flex items-center gap-2 ${
                activeCategory === category
                  ? `bg-gradient-to-r ${categoryMeta.tone} text-white shadow-md transform scale-105`
                  : 'bg-white/80 backdrop-blur-xl border border-white text-slate-600 hover:bg-white'
              }`}
            >
              <CategoryIcon size={16} /> {category}
            </button>
          );
        })}
      </div>

      <div className="px-4 mb-3">
        <div className="bg-white/70 backdrop-blur-xl border border-white/60 rounded-3xl p-4 md:p-5 grid grid-cols-1 md:grid-cols-3 gap-4 md:items-center shadow-sm">
          <div className="flex items-center gap-2 bg-slate-50 rounded-xl px-3 py-3">
            <Filter size={18} className="text-slate-500" />
            <div className="w-full">
              <p className="text-xs text-gray-500 font-bold mb-1">السعر الأقصى</p>
              <p className="text-sm font-black text-slate-900">{maxPrice} د.ج</p>
            </div>
          </div>
          <div>
            <input
              type="range"
              min={0}
              max={sliderMax}
              step={100}
              value={maxPrice}
              onChange={(event) => setMaxPrice(Number(event.target.value))}
              className="w-full accent-emerald-500"
            />
          </div>
          <div className="flex items-center gap-2 bg-slate-50 rounded-xl px-3 py-3">
            <ArrowUpDown size={18} className="text-slate-500" />
            <select
              value={sortBy}
              onChange={(event) => setSortBy(event.target.value)}
              className="w-full bg-transparent font-bold text-sm outline-none"
            >
              <option value="newest">الأحدث أولاً</option>
              <option value="price-low">السعر: من الأقل للأعلى</option>
              <option value="price-high">السعر: من الأعلى للأقل</option>
              <option value="discount">أعلى نسبة خصم</option>
            </select>
          </div>
        </div>
      </div>

      <div className="px-4 flex items-center justify-between text-xs md:text-sm mb-2">
        <p className="font-bold text-gray-500">{filteredProducts.length} منتج مطابق</p>
        <p className="font-bold text-gray-500">المفضلة: {favorites.length}</p>
      </div>

      {isLoadingProducts ? (
        <ProductsGridSkeleton />
      ) : filteredProducts.length === 0 ? (
        <div className="text-center py-20 text-gray-400 font-bold">
          <Package size={48} className="mx-auto mb-4 opacity-20" /> لا توجد منتجات بهذه المواصفات.
        </div>
      ) : (
        <div className="px-4 py-6 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 md:gap-8">
          <AnimatePresence mode="popLayout">
            {filteredProducts.map((product) => {
              const stock = clampStock(product.stock);
              const isFavorite = favorites.includes(product.id);
              const variants = normalizeProductVariants(product.variants);
              const selected = variantSelections[product.id] || {};
              const productOnSale = isProductOnSale(product);

              return (
                <Motion.div
                  layout
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={PAGE_TRANSITION}
                  key={product.id}
                  className="group bg-white/70 backdrop-blur-xl rounded-[1.5rem] border border-white/60 overflow-hidden flex flex-col shadow-sm hover:shadow-2xl transition-all duration-300"
                >
                  <div className="relative aspect-[4/5] bg-gray-50 overflow-hidden">
                    <img
                      src={product.image}
                      alt={product.name}
                      loading="lazy"
                      decoding="async"
                      className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-700"
                    />

                    <button
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleFavorite(product.id);
                      }}
                      className="absolute top-3 left-3 w-8 h-8 rounded-full bg-white/90 backdrop-blur flex items-center justify-center shadow-sm"
                    >
                      <Heart size={16} className={isFavorite ? 'text-rose-500 fill-rose-500' : 'text-slate-400'} />
                    </button>

                    <div className="absolute top-3 right-3 bg-white/90 backdrop-blur-md px-2 py-1 rounded-md text-[10px] md:text-xs font-bold text-slate-800 shadow-sm">
                      {product.category}
                    </div>

                    {productOnSale && (
                      <div className="absolute bottom-14 left-2 bg-rose-500 text-white px-2 py-1 rounded-md text-[10px] md:text-xs font-black shadow-sm">
                        -{getDiscountPercent(product)}%
                      </div>
                    )}

                    <div
                      className={`absolute bottom-14 right-2 px-2 py-1 rounded-md text-[10px] md:text-xs font-bold shadow-sm ${
                        stock === 0
                          ? 'bg-red-100 text-red-700'
                          : stock <= 3
                          ? 'bg-orange-100 text-orange-700'
                          : 'bg-emerald-100 text-emerald-700'
                      }`}
                    >
                      {stock === 0 ? 'نفد المخزون' : `متوفر: ${stock}`}
                    </div>
                  </div>

                  <div className="p-4 flex flex-col justify-between flex-1 gap-3">
                    <h3 className="font-bold text-slate-900 text-sm md:text-base line-clamp-2">{product.name}</h3>
                    <div>
                      <p className="font-black text-emerald-600 text-lg md:text-xl mt-1">{product.price} <span className="text-xs text-gray-400">د.ج</span></p>
                      {productOnSale && (
                        <p className="text-xs font-bold text-gray-400 line-through">{product.oldPrice} د.ج</p>
                      )}
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
                        <div className="flex flex-wrap gap-2">
                          {variants.colors.map((colorName) => {
                            const preset = COLOR_PRESETS.find((entry) => entry.name === colorName);
                            const isSelected = selected.color === colorName;
                            return (
                              <button
                                key={colorName}
                                onClick={() => setProductSelection(product.id, { color: colorName })}
                                className={`inline-flex items-center gap-1 px-2 py-1 rounded-md border text-[11px] font-black ${isSelected ? 'border-slate-900 text-slate-900 bg-slate-50' : 'border-slate-200 text-slate-600 bg-white'}`}
                              >
                                <span className="inline-block w-3.5 h-3.5 rounded-full border border-slate-300" style={{ backgroundColor: preset?.hex || '#e5e7eb' }} />
                                {colorName}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    <button
                      onClick={() => handleAddProduct(product)}
                      disabled={stock <= 0}
                      className={`w-full text-sm font-bold py-3 rounded-xl shadow-lg flex items-center justify-center gap-2 transition-colors active:scale-95 ${
                        stock <= 0
                          ? 'bg-slate-200 text-slate-500 cursor-not-allowed'
                          : 'bg-white/90 backdrop-blur text-slate-900 hover:bg-slate-900 hover:text-white'
                      }`}
                    >
                      <Plus size={18} />
                      <span>{stock <= 0 ? 'غير متوفر' : 'أضف للسلة'}</span>
                    </button>
                  </div>
                </Motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      )}
    </Motion.div>
  );
};

const FavoritesView = ({ products, favorites, toggleFavorite, onAddToCart, navigateTo, showToast }) => {
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
    <Motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={PAGE_TRANSITION} className="pb-24 md:pb-12 max-w-7xl mx-auto w-full px-4 md:px-6 pt-4 md:pt-10">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl md:text-3xl font-black text-slate-900">المفضلة</h2>
        <span className="text-xs md:text-sm font-black text-rose-500">{favoriteProducts.length} عنصر</span>
      </div>

      {favoriteProducts.length === 0 ? (
        <div className="rounded-3xl border border-slate-200 bg-white p-8 md:p-12 text-center shadow-sm">
          <Heart size={44} className="mx-auto mb-4 text-rose-200" />
          <p className="font-black text-slate-900 mb-2">لا توجد منتجات في المفضلة</p>
          <p className="text-sm font-bold text-gray-500 mb-5">أضف منتجاتك المفضلة للعودة إليها بسرعة.</p>
          <button onClick={() => navigateTo(ROUTES.home)} className="bg-slate-900 text-white px-6 py-3 rounded-full text-sm font-black">
            تصفح المنتجات
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-5">
          <AnimatePresence>
            {favoriteProducts.map((product) => {
              const variants = normalizeProductVariants(product.variants);
              const selected = variantSelections[product.id] || {};

              return (
                <Motion.div
                  key={product.id}
                  layout
                  initial={{ opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  className="rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-sm hover:shadow-lg transition-shadow"
                >
                  <img src={product.image} loading="lazy" decoding="async" className="w-full h-48 object-cover" alt={product.name} />
                  <div className="p-4 space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <h3 className="font-black text-slate-900 text-sm line-clamp-2">{product.name}</h3>
                      <button onClick={() => toggleFavorite(product.id)} className="text-rose-500">
                        <Heart size={18} className="fill-rose-500" />
                      </button>
                    </div>
                    <div>
                      <p className="font-black text-emerald-600">{product.price} د.ج</p>
                      {isProductOnSale(product) && <p className="text-xs text-gray-400 line-through font-bold">{product.oldPrice} د.ج</p>}
                    </div>

                    {variants.enableSizes && (
                      <div className="flex flex-wrap gap-1">
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
                    )}

                    {variants.enableColors && (
                      <div className="flex flex-wrap gap-1">
                        {variants.colors.map((colorName) => (
                          <button
                            key={colorName}
                            onClick={() => setProductSelection(product.id, { color: colorName })}
                            className={`px-2 py-1 rounded-md border text-[11px] font-black ${selected.color === colorName ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200'}`}
                          >
                            {colorName}
                          </button>
                        ))}
                      </div>
                    )}

                    <button
                      onClick={() => handleAddFavoriteProduct(product)}
                      className="w-full bg-slate-900 text-white py-2.5 rounded-xl text-sm font-black"
                    >
                      إضافة للسلة
                    </button>
                  </div>
                </Motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      )}
    </Motion.div>
  );
};

const CartView = ({
  cart,
  dispatchCart,
  navigateTo,
  siteConfig,
  showToast,
  setCheckoutPricing,
  onAddToCart,
  onRemoveFromCart,
  onCouponApplied,
}) => {
  const subtotal = useMemo(() => cart.reduce((sum, item) => sum + item.price * item.qty, 0), [cart]);
  const isCouponInputVisible = Boolean(siteConfig.showCouponInput);

  const availableCoupons = useMemo(
    () => normalizeCoupons(siteConfig.coupons, siteConfig.couponCode, siteConfig.couponDiscount),
    [siteConfig.coupons, siteConfig.couponCode, siteConfig.couponDiscount],
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
  }, [appliedCoupon, availableCoupons, cart.length, isCouponInputVisible]);

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
    showToast(`تم تطبيق خصم ${coupon.discount}% بنجاح`, 'success');
  };

  const cancelCoupon = () => {
    setAppliedCoupon(null);
    setCouponInput('');
    showToast('تم إلغاء الكوبون', 'success');
  };

  return (
    <Motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={PAGE_TRANSITION}
      className="pb-32 md:pb-14 min-h-screen max-w-7xl mx-auto w-full md:pt-10"
    >
      <div className="hidden md:flex justify-between items-end px-6 mb-8">
        <h2 className="text-3xl font-black text-slate-900 flex items-center gap-3">
          <ShoppingCart /> سلة المشتريات
        </h2>
      </div>

      {cart.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-[60vh] text-slate-400 px-4">
          <Package size={80} className="mb-6 opacity-20" />
          <p className="font-bold text-2xl mb-6 text-slate-800">سلتك فارغة تماماً</p>
          <button
            onClick={() => navigateTo(ROUTES.home)}
            className="bg-slate-900 text-white px-8 py-4 rounded-full font-bold shadow-lg hover:shadow-xl hover:bg-slate-800 transition-all"
          >
            ابدأ التسوق الآن
          </button>
        </div>
      ) : (
        <div className="px-4 md:px-6 flex flex-col lg:flex-row gap-8">
          <div className="flex-1 space-y-4">
            <AnimatePresence>
              {cart.map((item) => {
                const stock = Number.isFinite(Number(item.stock)) ? Number(item.stock) : Number.POSITIVE_INFINITY;

                return (
                  <Motion.div
                    layout
                    initial={{ opacity: 0, scale: 0.94, y: 8 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.92, y: -8 }}
                    key={item.cartKey || buildCartItemKey(item)}
                    className="bg-white p-3 md:p-6 rounded-3xl flex gap-4 shadow-sm border border-slate-200"
                  >
                    <img src={item.image} alt={item.name} loading="lazy" decoding="async" className="w-24 h-28 md:w-32 md:h-32 object-cover rounded-xl bg-gray-50" />
                    <div className="flex-1 flex flex-col justify-between py-1">
                      <div className="flex justify-between items-start">
                        <div>
                          <h3 className="font-bold text-slate-900 text-sm md:text-lg line-clamp-2 mb-1">{item.name}</h3>
                          {(item.selectedSize || item.selectedColor) && (
                            <p className="text-xs font-black text-slate-500">
                              {item.selectedSize ? `المقاس: ${item.selectedSize}` : ''}
                              {item.selectedSize && item.selectedColor ? ' | ' : ''}
                              {item.selectedColor ? `اللون: ${item.selectedColor}` : ''}
                            </p>
                          )}
                          <p className="font-black text-emerald-600 text-lg mt-2">{item.price} د.ج</p>
                        </div>
                        <button
                          onClick={() => onRemoveFromCart(item)}
                          className="text-gray-400 hover:text-red-500 bg-gray-50 hover:bg-red-50 p-2 rounded-lg transition-colors"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>

                      <div className="flex items-center gap-4 bg-gray-50 w-fit rounded-xl p-1 border border-gray-100 mt-4">
                        <button
                          onClick={() => dispatchCart({ type: 'DECREASE', payload: item })}
                          className="w-8 h-8 md:w-10 md:h-10 bg-white rounded-lg text-slate-600 shadow-sm font-bold"
                        >
                          -
                        </button>
                        <span className="font-bold text-sm md:text-base w-6 text-center">{item.qty}</span>
                        <button
                          onClick={() => {
                            if (item.qty >= stock) {
                              showToast('وصلت للكمية المتاحة من هذا المنتج', 'error');
                              return;
                            }
                            onAddToCart(item);
                          }}
                          className="w-8 h-8 md:w-10 md:h-10 bg-white rounded-lg text-slate-600 shadow-sm font-bold"
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

          <div className="lg:w-96">
            <div className="bg-white rounded-3xl p-6 md:p-8 shadow-[0_-10px_24px_rgba(15,23,42,0.08)] md:shadow-xl border border-slate-200 fixed bottom-[70px] md:sticky md:top-28 left-0 w-full md:w-auto z-30 pb-safe md:pb-8">
              <h3 className="hidden md:block font-black text-xl mb-6">ملخص الطلب</h3>

              {isCouponInputVisible && (
                <div className="mb-4 md:pt-4">
                  <p className="text-xs font-bold text-gray-500 mb-2">كوبون الخصم</p>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      dir="ltr"
                      value={couponInput}
                      onChange={(event) => setCouponInput(event.target.value)}
                      placeholder="COUPON"
                      className="flex-1 bg-gray-50 border border-gray-200 rounded-xl px-3 py-2 font-bold text-sm outline-none focus:ring-2 focus:ring-emerald-500"
                    />
                    <button onClick={applyCoupon} className="bg-slate-900 text-white px-4 rounded-xl font-bold text-sm">
                      تطبيق
                    </button>
                  </div>

                  {availableCoupons.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {availableCoupons.slice(0, 3).map((coupon) => {
                        const disabled = isCouponExpired(coupon) || isCouponExhausted(coupon);
                        return (
                          <button
                            key={coupon.id}
                            onClick={() => setCouponInput(coupon.code)}
                            disabled={disabled}
                            className={`text-[11px] px-2 py-1 rounded-full border font-black ${disabled ? 'bg-gray-100 text-gray-400 border-gray-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200'}`}
                          >
                            {coupon.code}
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {activeCoupon && (
                    <div className="mt-2 text-xs font-bold text-emerald-600 flex items-center justify-between">
                      <span>تم تطبيق {activeCoupon.code}</span>
                      <button onClick={cancelCoupon} className="text-rose-500">
                        إلغاء
                      </button>
                    </div>
                  )}
                </div>
              )}

              <div className="space-y-2 mb-4 md:border-t md:pt-4 border-gray-100">
                <div className="flex justify-between items-center text-sm font-bold text-gray-500">
                  <span>المجموع الفرعي</span>
                  <span>{subtotal} د.ج</span>
                </div>
                {discountValue > 0 && (
                  <div className="flex justify-between items-center text-sm font-bold text-emerald-600">
                    <span>الخصم</span>
                    <span>-{discountValue} د.ج</span>
                  </div>
                )}
                <div className="flex justify-between items-center pt-2 border-t border-gray-100">
                  <span className="text-gray-500 md:text-slate-900 font-medium md:font-black text-sm md:text-xl">الإجمالي</span>
                  <span className="text-2xl md:text-3xl font-black text-emerald-600">
                    {total} <span className="text-sm">د.ج</span>
                  </span>
                </div>
              </div>

              <button
                onClick={() => {
                  setCheckoutPricing({
                    subtotal,
                    discount: discountValue,
                    total,
                    couponCode: activeCoupon?.code || '',
                    couponId: activeCoupon?.id || '',
                  });
                  navigateTo(ROUTES.checkout);
                }}
                className="w-full bg-slate-900 text-white font-black py-4 md:py-5 rounded-xl md:rounded-2xl shadow-lg hover:shadow-xl hover:bg-emerald-500 active:scale-95 transition-all flex justify-center items-center gap-2"
              >
                إتمام الطلب <ChevronRight size={20} />
              </button>
            </div>
          </div>
        </div>
      )}
    </Motion.div>
  );
};

const CheckoutView = ({ cart, checkoutPricing, onAddOrder, navigateTo }) => {
  const { locations, isLoading: isLocationsLoading, error: locationsError } = useAlgeriaLocations(true);
  const { wilayaOptions, communesByWilaya, defaultWilayaCode } = locations;
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

  const communesForSelectedWilaya = useMemo(
    () => communesByWilaya[effectiveWilayaCode] || [],
    [communesByWilaya, effectiveWilayaCode],
  );

  const effectiveCommuneName = useMemo(() => {
    if (!formData.communeName) {
      return communesForSelectedWilaya[0]?.commune_name || '';
    }

    const hasCurrentCommune = communesForSelectedWilaya.some((entry) => entry.commune_name === formData.communeName);
    return hasCurrentCommune ? formData.communeName : communesForSelectedWilaya[0]?.commune_name || '';
  }, [communesForSelectedWilaya, formData.communeName]);

  const subtotalFromCart = cart.reduce((sum, item) => sum + item.price * item.qty, 0);
  const discount = Math.min(Number(checkoutPricing.discount) || 0, subtotalFromCart);
  const total = Number(checkoutPricing.total) || Math.max(0, subtotalFromCart - discount);

  const handleWilayaChange = (event) => {
    const nextWilayaCode = event.target.value;
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
      couponCode: checkoutPricing.couponCode || '',
      couponId: checkoutPricing.couponId || '',
    });
  };

  if (cart.length === 0) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
        <Package size={70} className="text-gray-300 mb-4" />
        <p className="text-2xl font-black text-slate-900 mb-2">لا يوجد منتجات للشراء</p>
        <p className="text-gray-500 font-bold mb-6">أضف منتجات أولاً ثم عد لإتمام الطلب.</p>
        <button onClick={() => navigateTo(ROUTES.home)} className="bg-slate-900 text-white px-8 py-4 rounded-full font-bold">
          العودة للتسوق
        </button>
      </div>
    );
  }

  return (
    <Motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={PAGE_TRANSITION}
      className="pb-24 min-h-screen max-w-5xl mx-auto w-full md:pt-12"
    >
      <div className="hidden md:flex items-center gap-3 mb-8 px-6">
        <button onClick={() => navigateTo(ROUTES.cart)} className="w-10 h-10 flex items-center justify-center bg-gray-100 rounded-full text-slate-600 rotate-180">
          <ChevronRight size={24} />
        </button>
        <h1 className="text-3xl font-black text-slate-900">معلومات التوصيل الآمنة</h1>
      </div>
      <div className="px-4 md:px-6">
        <form onSubmit={handleSubmit} className="bg-white md:shadow-xl md:p-10 md:rounded-[2rem] md:border border-slate-200 space-y-6 mt-6 md:mt-0">
          {locationsError && (
            <ErrorStateCard
              title="\u062a\u0639\u0630\u0631 \u062a\u062d\u0645\u064a\u0644 \u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0645\u0646\u0627\u0637\u0642"
              description={locationsError}
              actionLabel="\u0627\u0644\u0639\u0648\u062f\u0629 \u0644\u0644\u0645\u062a\u062c\u0631"
              onAction={() => navigateTo(ROUTES.home)}
            />
          )}

          {formError && (
            <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-bold text-red-700">
              {formError}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-bold text-gray-700 mb-2 ml-1">الاسم واللقب</label>
              <input
                required
                type="text"
                value={formData.name}
                onChange={(event) => setFormData({ ...formData, name: event.target.value })}
                className="w-full bg-gray-50 border border-gray-200 rounded-2xl py-4 px-4 font-bold outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-sm font-bold text-gray-700 mb-2 ml-1">رقم الهاتف</label>
              <input
                required
                type="tel"
                dir="ltr"
                value={formData.phone}
                onChange={(event) => setFormData({ ...formData, phone: event.target.value })}
                className="w-full bg-gray-50 border border-gray-200 rounded-2xl py-4 px-4 font-bold outline-none focus:ring-2 focus:ring-emerald-500 text-right"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-bold text-gray-700 mb-2 ml-1">الولاية</label>
              <select
                required
                value={effectiveWilayaCode}
                onChange={handleWilayaChange}
                className="w-full bg-gray-50 border border-gray-200 rounded-2xl py-4 px-4 font-bold outline-none focus:ring-2 focus:ring-emerald-500"
                disabled={isLocationsLoading || wilayaOptions.length === 0}
              >
                {isLocationsLoading && <option value="">جاري تحميل الولايات...</option>}
                {!isLocationsLoading && wilayaOptions.length === 0 && <option value="">لا تتوفر بيانات الولايات</option>}
                {wilayaOptions.map((wilaya) => (
                  <option key={wilaya.wilaya_code} value={wilaya.wilaya_code}>
                    {wilaya.wilaya_name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-bold text-gray-700 mb-2 ml-1">البلدية</label>
              <select
                required
                value={effectiveCommuneName}
                onChange={(event) => setFormData({ ...formData, communeName: event.target.value })}
                className="w-full bg-gray-50 border border-gray-200 rounded-2xl py-4 px-4 font-bold outline-none focus:ring-2 focus:ring-emerald-500"
                disabled={isLocationsLoading || communesForSelectedWilaya.length === 0}
              >
                {isLocationsLoading && <option value="">جاري تحميل البلديات...</option>}
                {!isLocationsLoading && communesForSelectedWilaya.length === 0 && <option value="">لا توجد بلديات</option>}
                {communesForSelectedWilaya.map((commune) => (
                  <option key={`${effectiveWilayaCode}-${commune.id}`} value={commune.commune_name}>
                    {commune.commune_name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="mt-10 pt-8 border-t border-gray-100 space-y-3">
            <div className="flex justify-between items-center text-sm font-bold text-gray-500">
              <span>المجموع الفرعي</span>
              <span>{subtotalFromCart} د.ج</span>
            </div>
            {discount > 0 && (
              <div className="flex justify-between items-center text-sm font-bold text-emerald-600">
                <span>الخصم</span>
                <span>-{discount} د.ج</span>
              </div>
            )}
            {checkoutPricing.couponCode && (
              <div className="flex justify-between items-center text-xs font-bold text-gray-500">
                <span>الكوبون المستخدم</span>
                <span dir="ltr">{checkoutPricing.couponCode}</span>
              </div>
            )}

            <div className="flex flex-col md:flex-row items-center justify-between gap-6 pt-2 border-t border-gray-100">
              <div className="text-center md:text-right w-full md:w-auto">
                <p className="text-gray-500 text-sm font-bold mb-1">المبلغ المطلوب:</p>
                <p className="text-3xl font-black text-slate-900">
                  {total} <span className="text-emerald-500">د.ج</span>
                </p>
              </div>
              <button
                type="submit"
                className="w-full md:w-auto md:px-12 bg-slate-900 text-white font-black py-5 rounded-2xl shadow-xl hover:shadow-2xl hover:bg-emerald-500 transition-all flex justify-center items-center gap-3 text-lg"
              >
                تأكيد الطلب نهائياً <CheckCircle size={24} />
              </button>
            </div>
          </div>
        </form>
      </div>
    </Motion.div>
  );
};

const AdminLogin = ({ showToast, onBackToStore, securityStatus }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSendingReset, setIsSendingReset] = useState(false);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [cooldownUntil, setCooldownUntil] = useState(0);

  const blockedUntilLabel = securityStatus?.blockedUntil
    ? new Date(securityStatus.blockedUntil).toLocaleString('ar-DZ')
    : '';

  const requestMeta = {
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
    page: '/admin/login',
  };

  const handleLogin = async (event) => {
    event.preventDefault();

    if (!auth) {
      showToast('Cannot log in because authentication service is unavailable.', 'error');
      return;
    }

    if (securityStatus?.blocked) {
      showToast(blockedUntilLabel ? '\u062a\u0645 \u062d\u0638\u0631 \u0627\u0644\u0648\u0635\u0648\u0644 \u0645\u0624\u0642\u062a\u064b\u0627 \u062d\u062a\u0649 ' + blockedUntilLabel : '\u062a\u0645 \u062d\u0638\u0631 \u0627\u0644\u0648\u0635\u0648\u0644 \u0645\u0624\u0642\u062a\u064b\u0627 \u0628\u0648\u0627\u0633\u0637\u0629 \u0646\u0638\u0627\u0645 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.', 'error');
      return;
    }

    if (!securityStatus?.loginEnabled) {
      showToast('Admin login is temporarily disabled by security controls.', 'error');
      return;
    }

    if (Date.now() < cooldownUntil) {
      showToast('Too many attempts. Please try again in a moment.', 'error');
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail || !password) {
      showToast('Please enter your email and password.', 'error');
      return;
    }

    try {
      setIsSubmitting(true);
      await signInWithEmailAndPassword(auth, normalizedEmail, password);
      setFailedAttempts(0);
      setCooldownUntil(0);
      showToast('Login successful');

      void trackClientSecurityEvent('admin_login_success', {
        source: 'admin_login',
        severity: 'info',
        summary: 'Admin login succeeded.',
        metadata: {
          ...requestMeta,
          email: normalizedEmail,
        },
      });
    } catch (error) {
      const errorCode = error?.code || '';
      const nextAttempts = failedAttempts + 1;
      setFailedAttempts(nextAttempts);

      const maxAttempts = securityStatus?.heightenedProtection ? 3 : 5;
      if (nextAttempts >= maxAttempts || errorCode === 'auth/too-many-requests') {
        const lockMs = 5 * 60 * 1000;
        setCooldownUntil(Date.now() + lockMs);
      }

      void trackClientSecurityEvent('admin_login_failed', {
        source: 'admin_login',
        severity: errorCode === 'auth/too-many-requests' ? 'high' : 'medium',
        summary: 'Admin login failed.',
        metadata: {
          ...requestMeta,
          email: normalizedEmail,
          attempts: nextAttempts,
          reason: errorCode || 'unknown',
        },
      });

      if (errorCode === 'auth/too-many-requests') {
        showToast('Too many attempts. Please wait and retry.', 'error');
      } else {
        showToast('Invalid credentials or insufficient permissions.', 'error');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleForgotPassword = async () => {
    if (!auth) {
      showToast('Unable to send reset link because service is unavailable.', 'error');
      return;
    }

    if (securityStatus?.blocked) {
      showToast(blockedUntilLabel ? '\u062a\u0645 \u062d\u0638\u0631 \u0627\u0644\u0648\u0635\u0648\u0644 \u0645\u0624\u0642\u062a\u064b\u0627 \u062d\u062a\u0649 ' + blockedUntilLabel : '\u062a\u0645 \u062d\u0638\u0631 \u0627\u0644\u0648\u0635\u0648\u0644 \u0645\u0624\u0642\u062a\u064b\u0627 \u0628\u0648\u0627\u0633\u0637\u0629 \u0646\u0638\u0627\u0645 \u0627\u0644\u062d\u0645\u0627\u064a\u0629.', 'error');
      return;
    }

    if (!securityStatus?.resetPasswordEnabled) {
      showToast('Password reset is temporarily disabled by security controls.', 'error');
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail) {
      showToast('Please enter your email address.', 'error');
      return;
    }

    try {
      setIsSendingReset(true);
      await sendPasswordResetEmail(auth, normalizedEmail);

      void trackClientSecurityEvent('forgot_password_requested', {
        source: 'admin_login',
        severity: 'medium',
        summary: 'Password reset was requested from admin login screen.',
        metadata: {
          ...requestMeta,
          email: normalizedEmail,
          status: 'accepted',
        },
      });
    } catch (error) {
      void trackClientSecurityEvent('forgot_password_requested', {
        source: 'admin_login',
        severity: 'medium',
        summary: 'Password reset request failed at provider layer.',
        metadata: {
          ...requestMeta,
          email: normalizedEmail,
          status: 'provider_rejected',
          reason: error?.code || 'unknown',
        },
      });
    } finally {
      setIsSendingReset(false);
      showToast('If the email is valid, a reset link will be sent.', 'success');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-100 via-emerald-50/40 to-teal-100/40 flex items-center justify-center p-4 md:p-8">
      <Motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={PAGE_TRANSITION}
        className="w-full max-w-md bg-white/95 backdrop-blur-xl border border-white shadow-2xl rounded-[2rem] p-6 md:p-8"
      >
        <div className="mb-8 text-center">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-slate-900 to-emerald-600 text-white flex items-center justify-center shadow-xl mb-4">
            <ShieldCheck size={30} />
          </div>
          <h2 className="text-2xl md:text-3xl font-black text-slate-900">Admin Sign In</h2>
          <p className="text-sm text-slate-500 font-bold mt-2">Secure admin access</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-bold text-slate-700 mb-2">Email Address</label>
            <div className="relative">
              <Mail size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="email"
                dir="ltr"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="admin@store.com"
                autoComplete="email"
                className="w-full rounded-2xl border border-slate-200 bg-slate-50/80 py-3.5 pr-11 pl-4 font-bold outline-none focus:border-emerald-500 focus:ring-4 focus:ring-emerald-100 transition"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-bold text-slate-700 mb-2">Password</label>
            <div className="relative">
              <Lock size={18} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="password"
                dir="ltr"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="********"
                autoComplete="current-password"
                className="w-full rounded-2xl border border-slate-200 bg-slate-50/80 py-3.5 pr-11 pl-4 font-bold outline-none focus:border-emerald-500 focus:ring-4 focus:ring-emerald-100 transition"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting || !auth || !securityStatus?.loginEnabled || securityStatus?.blocked}
            className="w-full mt-2 bg-slate-900 hover:bg-slate-800 text-white font-black py-3.5 rounded-2xl shadow-lg shadow-slate-900/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? 'Signing in...' : 'Sign In'}
          </button>

          <button
            type="button"
            onClick={handleForgotPassword}
            disabled={isSendingReset || !auth || !securityStatus?.resetPasswordEnabled || securityStatus?.blocked}
            className="w-full text-sm font-bold text-emerald-700 hover:text-emerald-600 py-2 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSendingReset ? 'Sending...' : 'Forgot Password'}
          </button>
        </form>
        <button
          type="button"
          onClick={onBackToStore}
          className="w-full text-sm font-bold text-slate-600 hover:text-slate-900 py-2 transition"
        >
          Back to Store
        </button>
        {securityStatus?.blocked && (
          <div className="mt-4 rounded-2xl bg-rose-50 border border-rose-200 p-3 text-xs font-bold text-rose-700 text-center">
            {blockedUntilLabel ? '\u062a\u0645 \u062a\u0639\u0644\u064a\u0642 \u0627\u0644\u0648\u0635\u0648\u0644 \u0645\u0646 \u0647\u0630\u0627 \u0627\u0644\u062c\u0647\u0627\u0632 \u062d\u062a\u0649 ' + blockedUntilLabel : '\u062a\u0645 \u062a\u0639\u0644\u064a\u0642 \u0627\u0644\u0648\u0635\u0648\u0644 \u0645\u0646 \u0647\u0630\u0627 \u0627\u0644\u062c\u0647\u0627\u0632 \u0645\u0624\u0642\u062a\u064b\u0627.'}
          </div>
        )}
        {!auth && (
          <div className="mt-4 rounded-2xl bg-orange-50 border border-orange-200 p-3 text-xs font-bold text-orange-700 text-center">
            Authentication service is not configured correctly.
          </div>
        )}
      </Motion.div>
    </div>
  );
};

const CustomerTrackView = ({ orders, customerOrders, navigateTo }) => {
  const text = {
    title: '\u062a\u062a\u0628\u0639 \u0627\u0644\u0637\u0644\u0628',
    desc: '\u0623\u062f\u062e\u0644 \u0631\u0642\u0645 \u0627\u0644\u0637\u0644\u0628 \u0644\u0644\u0628\u062d\u062b \u0639\u0646 \u0627\u0644\u062d\u0627\u0644\u0629',
    search: '\u0628\u062d\u062b',
    back: '\u0627\u0644\u0639\u0648\u062f\u0629 \u0644\u0644\u0645\u062a\u062c\u0631',
    placeholder: '#123456',
    notFound: '\u0644\u0645 \u064a\u062a\u0645 \u0627\u0644\u0639\u062b\u0648\u0631 \u0639\u0644\u0649 \u0627\u0644\u0637\u0644\u0628',
    orderNo: '\u0631\u0642\u0645 \u0627\u0644\u0637\u0644\u0628',
    total: '\u0627\u0644\u0625\u062c\u0645\u0627\u0644\u064a',
    date: '\u0627\u0644\u062a\u0627\u0631\u064a\u062e',
    products: '\u0627\u0644\u0645\u0646\u062a\u062c\u0627\u062a',
  };

  const [query, setQuery] = useState('');
  const [searched, setSearched] = useState(false);

  const mergedOrders = useMemo(() => {
    const map = new Map();
    (Array.isArray(customerOrders) ? customerOrders : []).forEach((order) => map.set(String(order.id), order));
    (Array.isArray(orders) ? orders : []).forEach((order) => map.set(String(order.id), order));
    return Array.from(map.values()).sort((a, b) => new Date(b.date || 0).getTime() - new Date(a.date || 0).getTime());
  }, [customerOrders, orders]);

  const foundOrder = useMemo(() => {
    const normalized = String(query || '').replace(/\D/g, '');
    if (!normalized) return null;
    return mergedOrders.find((entry) => String(entry.id).includes(normalized)) || null;
  }, [mergedOrders, query]);

  return (
    <Motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={PAGE_TRANSITION} className="max-w-5xl mx-auto w-full px-4 py-6 md:py-10 pb-24 md:pb-10">
      <div className="rounded-[2rem] border border-slate-700 bg-gradient-to-br from-slate-950 via-slate-900 to-slate-800 p-6 md:p-9 text-white shadow-2xl">
        <h1 className="text-2xl md:text-4xl font-black">{text.title}</h1>
        <p className="mt-2 text-sm md:text-base text-slate-200 font-bold">{text.desc}</p>

        <div className="mt-5 flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              inputMode="numeric"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={text.placeholder}
              className="w-full h-12 rounded-xl border border-slate-600 bg-slate-800/60 text-white pr-9 pl-4 outline-none focus:ring-2 focus:ring-emerald-400"
            />
          </div>
          <button type="button" onClick={() => setSearched(true)} className="h-12 px-6 rounded-xl bg-emerald-500 hover:bg-emerald-600 transition font-black">{text.search}</button>
          <button type="button" onClick={() => navigateTo(ROUTES.home)} className="h-12 px-6 rounded-xl bg-white/10 border border-white/20 hover:bg-white/20 transition font-black">{text.back}</button>
        </div>
      </div>

      {!searched ? null : !foundOrder ? (
        <div className="mt-6">
          <EmptyStateCard
            title={text.notFound}
            description="\u062a\u0623\u0643\u062f \u0645\u0646 \u0631\u0642\u0645 \u0627\u0644\u0637\u0644\u0628 \u0623\u0648 \u062c\u0631\u0651\u0628 \u0631\u0642\u0645\u0627\u064b \u0622\u062e\u0631."
            actionLabel="\u0627\u0644\u0639\u0648\u062f\u0629 \u0644\u0644\u0645\u062a\u062c\u0631"
            onAction={() => navigateTo(ROUTES.home)}
            icon={Package}
          />
        </div>
      ) : (
        <div className="mt-6 space-y-4">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs text-slate-500 font-bold">{text.orderNo}</p>
                <p className="text-xl font-black text-slate-900">#{String(foundOrder.id).slice(-8)}</p>
              </div>
              <OrderStatusPill status={foundOrder.status} />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 mt-4 text-sm font-bold">
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">{text.date}</p>
                <p className="text-slate-900">{new Date(foundOrder.date).toLocaleDateString('ar-DZ')}</p>
              </div>
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">{text.total}</p>
                <p className="text-slate-900">{Number(foundOrder.totalPrice) || 0} د.ج</p>
              </div>
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-3">
                <p className="text-slate-500">{text.products}</p>
                <p className="text-slate-900">{Array.isArray(foundOrder.items) ? foundOrder.items.length : 0}</p>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6 shadow-sm">
            <div className="space-y-2">
              {(foundOrder.items || []).map((item, index) => (
                <div key={String(foundOrder.id) + '-' + String(index)} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 flex items-center justify-between gap-2 text-sm font-bold">
                  <div>
                    <p className="text-slate-900">{item.name}</p>
                    {(item.selectedSize || item.selectedColor) && (
                      <p className="text-xs text-slate-500">
                        {item.selectedSize ? 'Size: ' + String(item.selectedSize) : ''}
                        {item.selectedSize && item.selectedColor ? ' | ' : ''}
                        {item.selectedColor ? 'Color: ' + String(item.selectedColor) : ''}
                      </p>
                    )}
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

const LazyAdminCMS = lazy(() => import('./pages/AdminCMS'));

export default function App() {
  const [currentRoute, setCurrentRoute] = useState(ROUTES.home);
  const [cart, dispatchCart] = useReducer(cartReducer, readStorage(STORAGE_KEYS.cart, []), normalizeCartItems);
  const [orders, setOrders] = useState(() => normalizeOrders(readStorage(STORAGE_KEYS.orders, [])));
  const [customerOrders, setCustomerOrders] = useState(() => normalizeOrders(readStorage(STORAGE_KEYS.customerOrders, [])));
  const [adminUser, setAdminUser] = useState(null);
  const [isAuthReady, setIsAuthReady] = useState(!auth);
  const { toast, showToast } = useToast();

  const [siteConfig, setSiteConfig] = useState(() => normalizeSiteConfig(readStorage(STORAGE_KEYS.siteConfig, {})));

  const [products, setProducts] = useState(() =>
    normalizeProducts(readStorage(STORAGE_KEYS.products, initialProductsData)),
  );

  const [favorites, setFavorites] = useState(() => {
    const stored = readStorage(STORAGE_KEYS.favorites, []);
    return Array.isArray(stored) ? stored : [];
  });

  const [searchQuery, setSearchQuery] = useState('');
  const [checkoutPricing, setCheckoutPricing] = useState({ subtotal: 0, discount: 0, total: 0, shippingFee: 0, couponCode: '', couponId: '' });
  const [isRemoteBootstrapped, setIsRemoteBootstrapped] = useState(false);
  const [syncStatus, setSyncStatus] = useState(hasFirebaseConfig ? 'syncing' : 'local');
  const [adminTheme, setAdminTheme] = useState(() => (readStorage(STORAGE_KEYS.adminTheme, 'dark') === 'dark' ? 'dark' : 'light'));
  const [isCartAnimating, setIsCartAnimating] = useState(false);
  const [isCouponCelebrating, setIsCouponCelebrating] = useState(false);
  const [isOrderCelebrating, setIsOrderCelebrating] = useState(false);
  const [securityStatus, setSecurityStatus] = useState({
    loginEnabled: true,
    resetPasswordEnabled: true,
    heightenedProtection: false,
    blocked: false,
    blockedUntil: '',
    blockedReason: '',
  });
  const cartAnimationTimeoutRef = useRef(null);
  const audioContextRef = useRef(null);
  const isAdminAuth = Boolean(adminUser);
  const isProductsLoading = hasFirebaseConfig && !isRemoteBootstrapped;

  useEffect(() => {
    const allowed = new Set(normalizeProductCategories(siteConfig.productCategories));
    if (!allowed.size) return;

    setProducts((previousProducts) => {
      let changed = false;
      const next = previousProducts.map((product) => {
        if (allowed.has(product.category)) return product;
        changed = true;
        return { ...product, category: '\u0623\u062e\u0631\u0649' };
      });
      return changed ? next : previousProducts;
    });
  }, [siteConfig.productCategories]);

  useEffect(() => {
    if (!auth) {
      setIsAuthReady(true);
      return undefined;
    }

    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setAdminUser(user);
      setIsAuthReady(true);
    });

    return () => unsubscribe();
  }, []);

  useEffect(() => {
    let active = true;
    const loadStatus = async () => {
      try {
        const status = await fetchPublicSecurityStatus();
        if (active && status && typeof status === 'object') {
          setSecurityStatus({
            loginEnabled: Boolean(status.loginEnabled ?? true),
            resetPasswordEnabled: Boolean(status.resetPasswordEnabled ?? true),
            heightenedProtection: Boolean(status.heightenedProtection ?? false),
            blocked: Boolean(status.blocked ?? false),
            blockedUntil: String(status.blockedUntil || ''),
            blockedReason: String(status.blockedReason || ''),
          });
        }
      } catch {
        // keep secure defaults
      }
    };

    void loadStatus();
    const timer = window.setInterval(() => {
      void loadStatus();
    }, 60000);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [isAdminAuth]);

  useEffect(() => {
    let active = true;

    const bootstrapRemoteData = async () => {
      if (!hasFirebaseConfig) {
        setIsRemoteBootstrapped(true);
        return;
      }

      try {
        const remoteData = await loadStoreBundle({
          products: normalizeProducts(readStorage(STORAGE_KEYS.products, initialProductsData)),
          orders: normalizeOrders(readStorage(STORAGE_KEYS.orders, [])),
          siteConfig: normalizeSiteConfig(readStorage(STORAGE_KEYS.siteConfig, {})),
        });
        if (!active) return;

        setProducts(normalizeProducts(remoteData.products));
        setOrders(normalizeOrders(remoteData.orders));
        setSiteConfig(normalizeSiteConfig(remoteData.siteConfig || {}));
        setSyncStatus('online');
      } catch {
        if (active) {
          setSyncStatus('local');
        }
      } finally {
        if (active) {
          setIsRemoteBootstrapped(true);
        }
      }
    };

    bootstrapRemoteData();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.orders, orders);
  }, [orders]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.cart, cart);
  }, [cart]);

  useEffect(() => {
    setCustomerOrders((previous) => mergeCustomerOrdersWithOrders(previous, orders));
  }, [orders]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.customerOrders, customerOrders);
  }, [customerOrders]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.products, products);
  }, [products]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.siteConfig, siteConfig);
  }, [siteConfig]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.favorites, favorites);
  }, [favorites]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.adminTheme, adminTheme);
  }, [adminTheme]);

  useEffect(() => {
    if (typeof document === 'undefined') return;

    const storeName = String(siteConfig?.name || '\u0623\u0646\u0627\u0642\u0629 \u0633\u062a\u0648\u0631').trim() || '\u0623\u0646\u0627\u0642\u0629 \u0633\u062a\u0648\u0631';
    document.title = `${storeName} | \u0645\u062a\u062c\u0631 \u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a`;

    const iconHref = String(siteConfig?.logoUrl || '').trim() || '/vite.svg';
    let iconLink = document.querySelector("link[rel='icon']");

    if (!iconLink) {
      iconLink = document.createElement('link');
      iconLink.setAttribute('rel', 'icon');
      document.head.appendChild(iconLink);
    }

    iconLink.setAttribute('href', iconHref);
    iconLink.setAttribute('type', iconHref.endsWith('.svg') ? 'image/svg+xml' : 'image/png');
  }, [siteConfig?.name, siteConfig?.logoUrl]);

  useEffect(() => () => {
    if (cartAnimationTimeoutRef.current) {
      window.clearTimeout(cartAnimationTimeoutRef.current);
    }
  }, []);

  useEffect(() => {
    if (!hasFirebaseConfig || !isRemoteBootstrapped) return;

    let active = true;
    setSyncStatus('syncing');

    saveOrdersRemote(orders)
      .then(() => {
        if (active) setSyncStatus('online');
      })
      .catch(() => {
        if (active) setSyncStatus('local');
      });

    return () => {
      active = false;
    };
  }, [orders, isRemoteBootstrapped]);

  useEffect(() => {
    if (!hasFirebaseConfig || !isRemoteBootstrapped) return;

    let active = true;
    setSyncStatus('syncing');

    saveProductsRemote(products)
      .then(() => {
        if (active) setSyncStatus('online');
      })
      .catch(() => {
        if (active) setSyncStatus('local');
      });

    return () => {
      active = false;
    };
  }, [products, isRemoteBootstrapped]);

  useEffect(() => {
    if (!hasFirebaseConfig || !isRemoteBootstrapped) return;

    let active = true;
    setSyncStatus('syncing');

    saveSiteConfigRemote(siteConfig)
      .then(() => {
        if (active) setSyncStatus('online');
      })
      .catch(() => {
        if (active) setSyncStatus('local');
      });

    return () => {
      active = false;
    };
  }, [siteConfig, isRemoteBootstrapped]);

  const cartCount = cart.reduce((total, item) => total + item.qty, 0);
  const customerOrdersCount = customerOrders.length;

  const storefrontCategories = useMemo(
    () => ['\u0627\u0644\u0643\u0644', ...normalizeProductCategories(siteConfig.productCategories)],
    [siteConfig.productCategories],
  );

  const storefrontCategoryMeta = useMemo(() => {
    const tones = [
      'from-cyan-600 to-sky-700',
      'from-emerald-500 to-teal-600',
      'from-violet-500 to-indigo-600',
      'from-amber-500 to-orange-600',
      'from-rose-500 to-pink-600',
    ];

    const map = { ...CATEGORY_META };
    storefrontCategories.forEach((category, index) => {
      if (!map[category]) {
        map[category] = {
          icon: Sparkles,
          tone: tones[index % tones.length],
        };
      }
    });

    return map;
  }, [storefrontCategories]);


  const navigateTo = (route) => {
    const allowedRoutes = new Set(Object.values(ROUTES));
    setCurrentRoute(allowedRoutes.has(route) ? route : ROUTES.home);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const playUiSound = (type = 'success') => {
    if (typeof window === 'undefined') return;

    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;

      if (!audioContextRef.current) {
        audioContextRef.current = new AudioCtx();
      }

      const ctx = audioContextRef.current;
      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      const oscillator = ctx.createOscillator();
      const gainNode = ctx.createGain();

      const tones = {
        add: [680, 920, 0.16],
        remove: [420, 220, 0.18],
        coupon: [760, 1040, 0.2],
        order: [520, 860, 0.24],
        success: [620, 900, 0.18],
      };

      const [startFreq, endFreq, duration] = tones[type] || tones.success;
      oscillator.type = type === 'remove' ? 'sawtooth' : 'triangle';
      oscillator.frequency.setValueAtTime(startFreq, ctx.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(endFreq, ctx.currentTime + duration * 0.45);

      gainNode.gain.setValueAtTime(0.001, ctx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.085, ctx.currentTime + 0.02);
      gainNode.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration);

      oscillator.connect(gainNode);
      gainNode.connect(ctx.destination);
      oscillator.start();
      oscillator.stop(ctx.currentTime + duration + 0.02);
    } catch {
      // optional enhancement only
    }
  };

  const triggerCartFeedback = () => {
    setIsCartAnimating(true);

    if (cartAnimationTimeoutRef.current) {
      window.clearTimeout(cartAnimationTimeoutRef.current);
    }

    cartAnimationTimeoutRef.current = window.setTimeout(() => {
      setIsCartAnimating(false);
    }, 450);

    playUiSound('add');
  };

  const triggerCouponCelebration = () => {
    setIsCouponCelebrating(true);
    window.setTimeout(() => setIsCouponCelebrating(false), 760);
  };

  const triggerOrderCelebration = () => {
    setIsOrderCelebrating(true);
    window.setTimeout(() => setIsOrderCelebrating(false), 1000);
  };

  const handleAddToCart = (item) => {
    dispatchCart({ type: 'ADD_ITEM', payload: item });
    triggerCartFeedback();
  };

  const handleRemoveFromCart = (item) => {
    dispatchCart({ type: 'REMOVE_ITEM', payload: item });
    playUiSound('remove');
    showToast('تم حذف المنتج من السلة', 'error');
  };

  const handleAdminLogout = async () => {
    try {
      if (auth) {
        await signOut(auth);
      } else {
        setAdminUser(null);
      }
      showToast('تم تسجيل الخروج من لوحة الإدارة');
    } catch {
      showToast('تعذر تسجيل الخروج حالياً', 'error');
    }
  };

  const toggleFavorite = (productId) => {
    setFavorites((previous) =>
      previous.includes(productId)
        ? previous.filter((id) => id !== productId)
        : [productId, ...previous],
    );
  };

  const notifyOrder = async (order) => {
    try {
      await sendOrderNotification(order);
    } catch (error) {
      showToast(String(error?.message || 'تم تسجيل الطلب، لكن تعذر إرسال الإشعار.'), 'error');
    }
  };

  const handleAddOrder = (customerData, cartItems, pricing) => {
    if (!cartItems.length) {
      showToast('السلة فارغة', 'error');
      return;
    }

    const stockCheck = validateStockAvailability(cartItems, products);
    if (!stockCheck.ok) {
      showToast(stockCheck.issues[0], 'error');
      return;
    }

    const subtotal = Number(pricing?.subtotal) || cartItems.reduce((sum, item) => sum + item.price * item.qty, 0);
    const discount = Math.min(Number(pricing?.discount) || 0, subtotal);
    const shippingFee = Math.max(0, Number(pricing?.shippingFee) || 0);
    const totalPrice = Math.max(0, Number(pricing?.total) || subtotal - discount + shippingFee);

    const newOrder = {
      id: Date.now(),
      customer: customerData,
      items: cartItems,
      subtotal,
      discount,
      couponCode: pricing?.couponCode || '',
      couponId: pricing?.couponId || '',
      totalPrice,
      shippingFee,
      status: 'pending',
      date: new Date().toISOString(),
    };

    try {
      setOrders((previous) => [newOrder, ...previous]);
      setCustomerOrders((previous) => [newOrder, ...previous]);

      setProducts((previousProducts) =>
        previousProducts.map((product) => {
          const orderedItem = cartItems.find((item) => item.id === product.id);
          if (!orderedItem) return product;

          return {
            ...product,
            stock: Math.max(0, clampStock(product.stock) - orderedItem.qty),
          };
        }),
      );

      if (pricing?.couponCode) {
        setSiteConfig((previousSiteConfig) => {
          const nextCoupons = normalizeCoupons(
            previousSiteConfig.coupons,
            previousSiteConfig.couponCode,
            previousSiteConfig.couponDiscount,
          ).map((coupon) => {
            const byId = pricing?.couponId && coupon.id === pricing.couponId;
            const byCode = normalizeCouponCode(coupon.code) === normalizeCouponCode(pricing.couponCode);
            if (!byId && !byCode) return coupon;
            return { ...coupon, usedCount: (Number(coupon.usedCount) || 0) + 1 };
          });

          return {
            ...previousSiteConfig,
            coupons: nextCoupons,
          };
        });
      }

      dispatchCart({ type: 'CLEAR' });
      setCheckoutPricing({ subtotal: 0, discount: 0, total: 0, shippingFee: 0, couponCode: '', couponId: '' });
      playUiSound('order');
      triggerOrderCelebration();
      showToast('تم إرسال طلبك بنجاح! شكراً لثقتك.', 'success');
      navigateTo(ROUTES.home);

      notifyOrder(newOrder);
    } catch {
      showToast('حدث خطأ أثناء حفظ الطلب. حاول مجددًا.', 'error');
    }
  };

  if (!siteConfig.isOnline && currentRoute !== ROUTES.admin && !isAdminAuth) {
    return (
      <div dir="rtl" style={{ fontFamily: "'Alexandria', sans-serif" }}>
        <style>{`@import url('https://fonts.googleapis.com/css2?family=Alexandria:wght@400;500;600;700;800;900&display=swap');`}</style>
        <MaintenanceView siteName={siteConfig.name} onOpenAdmin={() => navigateTo(ROUTES.admin)} />
      </div>
    );
  }

  if (securityStatus.blocked && !isAdminAuth) {
    return (
      <div dir="rtl" style={{ fontFamily: "'Alexandria', sans-serif" }}>
        <style>{`@import url('https://fonts.googleapis.com/css2?family=Alexandria:wght@400;500;600;700;800;900&display=swap');`}</style>
        <BlockedAccessView
          siteName={siteConfig.name}
          blockedUntil={securityStatus.blockedUntil}
          blockedReason={securityStatus.blockedReason}
          onRefresh={() => window.location.reload()}
        />
      </div>
    );
  }
  const isCheckoutOrAdmin = currentRoute === ROUTES.checkout || currentRoute === ROUTES.admin;

  return (
    <div className="min-h-[100dvh] bg-transparent font-sans text-right selection:bg-emerald-200" dir="rtl">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Alexandria:wght@400;500;600;700;800;900&display=swap');
        body { font-family: 'Alexandria', sans-serif; margin: 0; padding: 0; }
        .no-scrollbar::-webkit-scrollbar { display: none; }
        .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
        .pb-safe { padding-bottom: env(safe-area-inset-bottom, 20px); }
        input, select, button { -webkit-tap-highlight-color: transparent; }
        @keyframes cart-shake {
          0% { transform: translateX(0); }
          25% { transform: translateX(-2px); }
          50% { transform: translateX(2px); }
          75% { transform: translateX(-1px); }
          100% { transform: translateX(0); }
        }
        .animate-cart-shake { animation: cart-shake 0.38s ease-in-out; }
        @keyframes float-slow {
          0% { transform: translateY(0px); }
          50% { transform: translateY(-8px); }
          100% { transform: translateY(0px); }
        }
        .animate-float-slow { animation: float-slow 6s ease-in-out infinite; }
        .animate-float-slow-reverse { animation: float-slow 6.8s ease-in-out infinite reverse; }
        @keyframes skeleton-shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        .skeleton-shimmer {
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.55), transparent);
          animation: skeleton-shimmer 1.2s infinite;
        }
      `}</style>

      <Toast toast={toast} transition={PAGE_TRANSITION} />
      <AnimatePresence>
        {isCouponCelebrating && (
          <Motion.div
            key="coupon-pulse"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 1.05 }}
            className="pointer-events-none fixed inset-0 z-[11000]"
          >
            <div className="absolute left-1/2 top-24 h-44 w-44 -translate-x-1/2 rounded-full bg-emerald-400/25 blur-3xl" />
          </Motion.div>
        )}
      </AnimatePresence>
      <AnimatePresence>
        {isOrderCelebrating && (
          <Motion.div
            key="order-burst"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="pointer-events-none fixed inset-0 z-[11000]"
          >
            <Motion.div
              initial={{ scale: 0.7, opacity: 0 }}
              animate={{ scale: 1.25, opacity: 0.95 }}
              exit={{ scale: 1.5, opacity: 0 }}
              transition={{ duration: 0.7, ease: 'easeOut' }}
              className="absolute left-1/2 top-1/2 h-52 w-52 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-emerald-300/70"
            />
          </Motion.div>
        )}
      </AnimatePresence>
      {currentRoute !== ROUTES.admin && <CustomerNoticeCenter notices={siteConfig.customerNotices} />}

      {currentRoute !== ROUTES.admin && (
        <>
          <AnnouncementBar text={siteConfig.announcement} />
          <DesktopNavbar
            currentRoute={currentRoute}
            navigateTo={navigateTo}
            cartCount={cartCount}
            isAdminAuth={isAdminAuth}
            isCartAnimating={isCartAnimating}
            onAdminLogout={handleAdminLogout}
            siteName={siteConfig.name}
            siteLogo={siteConfig.logoUrl}
            searchQuery={searchQuery}
            setSearchQuery={setSearchQuery}
            favoritesCount={favorites.length}
            customerOrdersCount={customerOrdersCount}
          />
          {currentRoute === ROUTES.home && <MobileHeader title={siteConfig.name} siteName={siteConfig.name} siteLogo={siteConfig.logoUrl} cartCount={cartCount} navigateTo={navigateTo} isCartAnimating={isCartAnimating} />}
          {currentRoute === ROUTES.offers && <MobileHeader title={"\u0627\u0644\u0639\u0631\u0648\u0636"} siteName={siteConfig.name} siteLogo={siteConfig.logoUrl} cartCount={cartCount} navigateTo={navigateTo} isCartAnimating={isCartAnimating} />}
          {currentRoute === ROUTES.favorites && <MobileHeader title={"\u0627\u0644\u0645\u0641\u0636\u0644\u0629"} siteName={siteConfig.name} siteLogo={siteConfig.logoUrl} cartCount={cartCount} navigateTo={navigateTo} isCartAnimating={isCartAnimating} />}
          {currentRoute === ROUTES.cart && <MobileHeader title={"\u0627\u0644\u0633\u0644\u0629"} siteName={siteConfig.name} siteLogo={siteConfig.logoUrl} cartCount={cartCount} navigateTo={navigateTo} isCartAnimating={isCartAnimating} />}
          {currentRoute === ROUTES.track && <MobileHeader title={"\u062A\u062A\u0628\u0639 \u0627\u0644\u0637\u0644\u0628"} siteName={siteConfig.name} siteLogo={siteConfig.logoUrl} cartCount={cartCount} navigateTo={navigateTo} isCartAnimating={isCartAnimating} />}
        </>
      )}

      <main className="relative w-full">
        <AnimatePresence mode="wait">
          {(currentRoute === ROUTES.home || currentRoute === ROUTES.offers) && (
            <StorefrontHome
              key={currentRoute}
              products={products}
              onAddToCart={handleAddToCart}
              showToast={showToast}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              favorites={favorites}
              toggleFavorite={toggleFavorite}
              isLoadingProducts={isProductsLoading}
              currentRoute={currentRoute}
              navigateTo={navigateTo}
              siteConfig={siteConfig}
              routes={ROUTES}
              categories={storefrontCategories}
              categoryMeta={storefrontCategoryMeta}
              helpers={{
                normalizeProductVariants,
                clampStock,
                isProductOnSale,
                getDiscountPercent,
                colorPresets: COLOR_PRESETS,
                normalizeHeroConfig,
              }}
              pageTransition={PAGE_TRANSITION}
            />
          )}

          {currentRoute === ROUTES.cart && (
            <StorefrontCart
              key="cart"
              cart={cart}
              dispatchCart={dispatchCart}
              navigateTo={navigateTo}
              siteConfig={siteConfig}
              showToast={showToast}
              setCheckoutPricing={setCheckoutPricing}
              onAddToCart={handleAddToCart}
              onRemoveFromCart={handleRemoveFromCart}
              onCouponApplied={() => {
                playUiSound('coupon');
                triggerCouponCelebration();
              }}
              routes={ROUTES}
              helpers={{
                buildCartItemKey,
                normalizeCoupons,
                normalizeCouponCode,
                isCouponApplicable,
                isCouponExpired,
                isCouponExhausted,
              }}
              pageTransition={PAGE_TRANSITION}
            />
          )}

          {currentRoute === ROUTES.favorites && (
            <StorefrontFavorites
              key="favorites"
              products={products}
              favorites={favorites}
              toggleFavorite={toggleFavorite}
              onAddToCart={handleAddToCart}
              navigateTo={navigateTo}
              showToast={showToast}
              routes={ROUTES}
              helpers={{
                normalizeProductVariants,
                isProductOnSale,
                colorPresets: COLOR_PRESETS,
              }}
              pageTransition={PAGE_TRANSITION}
            />
          )}

          {currentRoute === ROUTES.checkout && (
            <StorefrontCheckout
              key="checkout"
              cart={cart}
              checkoutPricing={checkoutPricing}
              siteConfig={siteConfig}
              onAddOrder={handleAddOrder}
              navigateTo={navigateTo}
              routes={ROUTES}
              pageTransition={PAGE_TRANSITION}
            />
          )}

          {currentRoute === ROUTES.track && (
            <StorefrontTrack
              key="track"
              orders={orders}
              customerOrders={customerOrders}
              navigateTo={navigateTo}
              routes={ROUTES}
              helpers={{ getOrderStatusMeta }}
              pageTransition={PAGE_TRANSITION}
            />
          )}

          {currentRoute === ROUTES.admin && !isAuthReady && (
            <Motion.div key="auth-loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="min-h-[70vh] flex items-center justify-center">
              <div className="bg-white border border-slate-200 rounded-3xl px-8 py-6 shadow-sm text-center">
                <p className="text-slate-600 font-black">جاري التحقق من الجلسة...</p>
              </div>
            </Motion.div>
          )}

          {currentRoute === ROUTES.admin && isAuthReady && !isAdminAuth && (
            <AdminLogin key="login" showToast={showToast} onBackToStore={() => navigateTo(ROUTES.home)} securityStatus={securityStatus} />
          )}

          {currentRoute === ROUTES.admin && isAuthReady && isAdminAuth && (
            <Suspense
              fallback={(
                <Motion.div key="admin-loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="min-h-[70vh] flex items-center justify-center">
                  <div className="bg-white border border-slate-200 rounded-3xl px-8 py-6 shadow-sm text-center">
                    <p className="text-slate-600 font-black">جاري تحميل لوحة الإدارة...</p>
                  </div>
                </Motion.div>
              )}
            >
              <LazyAdminCMS
                key="admin"
                orders={orders}
                setOrders={setOrders}
                products={products}
                setProducts={setProducts}
                siteConfig={siteConfig}
                setSiteConfig={setSiteConfig}
                onLogout={async () => {
                  await handleAdminLogout();
                  navigateTo(ROUTES.home);
                }}
                adminUser={adminUser}
                syncStatus={syncStatus}
                adminTheme={adminTheme}
                setAdminTheme={setAdminTheme}
                showToast={showToast}
                helpers={{
                  CATEGORIES: storefrontCategories,
                  DEFAULT_PRODUCT_VARIANTS,
                  SHOE_SIZES,
                  CLOTHING_SIZES,
                  COLOR_PRESETS,
                  ORDER_STATUSES,
                  clampStock,
                  normalizeCoupons,
                  normalizeCouponCode,
                  clampDiscount,
                  clampUses,
                  normalizeProductVariants,
                  isProductOnSale,
                  getDiscountPercent,
                  buildCartItemKey,
                  getOrderStatusMeta,
                  PAGE_TRANSITION,
                }}
              />
            </Suspense>
          )}
        </AnimatePresence>
      </main>

      {currentRoute !== ROUTES.admin && (
        <FloatingWhatsAppButton
          phoneNumber={siteConfig.whatsappNumber}
          facebookUrl={siteConfig.facebookUrl}
          instagramUrl={siteConfig.instagramUrl}
        />
      )}
      {currentRoute !== ROUTES.admin && currentRoute !== ROUTES.checkout && <StoreFooter siteName={siteConfig.name} siteLogo={siteConfig.logoUrl} navigateTo={navigateTo} />}
      {!isCheckoutOrAdmin && (
        <BottomNav
          currentRoute={currentRoute}
          navigateTo={navigateTo}
          cartCount={cartCount}
          isCartAnimating={isCartAnimating}
          favoritesCount={favorites.length}
          customerOrdersCount={customerOrdersCount}
        />
      )}
    </div>
  );
}























































































































































