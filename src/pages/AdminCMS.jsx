import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion as Motion } from 'framer-motion';
import {
  AlertTriangle,
  CheckCircle,
  CreditCard,
  Edit3,
  LayoutDashboard,
  LogOut,
  MessageCircle,
  Megaphone,
  MoonStar,
  Package,
  Palette,
  Plus,
  Power,
  Ruler,
  Search,
  Filter,
  CalendarDays,
  Settings,
  ShieldCheck,
  ShieldAlert,
  ShoppingCart,
  Sparkles,
  Store,
  SunMedium,
  Trash2,
} from 'lucide-react';
import { uploadProductImage } from '../services/storeService';
import { validateImageFile } from '../services/imgbbService';
import { getOrderDateRange, isWithinDateRange, toDateInputValue } from '../utils/orderDateFilters';
import AdminSecurityCenter from '../components/AdminSecurityCenter';
import { logAdminSecurityAction } from '../services/securityApi';
import {
  fetchTelegramIntegration,
  saveTelegramIntegration,
  sendAdminTelegramNotification,
  testTelegramIntegration,
} from '../services/telegramApi';
import { loadAlgeriaWilayas } from '../utils/algeriaLocations';

const OrderStatusPill = ({ status, getOrderStatusMeta }) => {
  const meta = getOrderStatusMeta(status);
  return <span className={`text-xs font-black px-3 py-1 rounded-full border ${meta.className}`}>{meta.label}</span>;
};
const ORDER_PERIOD_OPTIONS = [
  { key: 'today', label: 'طلبيات اليوم' },
  { key: 'yesterday', label: 'طلبيات البارحة' },
  { key: 'week', label: 'طلبيات هذا الأسبوع' },
  { key: 'month', label: 'طلبيات هذا الشهر' },
  { key: 'all', label: 'كل الطلبيات' },
  { key: 'custom', label: 'فترة مخصصة' },
];
const TELEGRAM_NOTIFICATION_DEFAULTS = {
  newOrder: true,
  orderStatus: true,
  systemErrors: false,
  adminActions: true,
};

const ALL_CATEGORY_LABEL = 'الكل';
const DEFAULT_CATEGORY_NAME = 'أخرى';
const NOTICE_LEVEL_OPTIONS = [
  { value: 'normal', label: 'عادي' },
  { value: 'important', label: 'مهم' },
  { value: 'critical', label: 'مهم جدًا' },
];

const AdminCMS = ({
  orders,
  setOrders,
  products,
  setProducts,
  siteConfig,
  setSiteConfig,
  onLogout,
  showToast,
  syncStatus,
  adminUser,
  adminTheme,
  setAdminTheme,
  helpers,
}) => {
  const {
    CATEGORIES,
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
  } = helpers;
  const isCouponExpired = (coupon) =>
    Boolean(coupon?.expiresAt) && new Date(coupon.expiresAt).getTime() < Date.now();
  const isCouponExhausted = (coupon) =>
    (Number(coupon?.usedCount) || 0) >= (Number(coupon?.maxUses) || 0);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showProductForm, setShowProductForm] = useState(false);
  const [editingProduct, setEditingProduct] = useState(null);
  const [productForm, setProductForm] = useState({
    name: '',
    description: '',
    price: '',
    oldPrice: '',
    category: CATEGORIES.find((entry) => entry !== ALL_CATEGORY_LABEL) || DEFAULT_CATEGORY_NAME,
    image: '',
    images: [],
    stock: 10,
    variants: { ...DEFAULT_PRODUCT_VARIANTS },
  });
  const [productImageUrlInput, setProductImageUrlInput] = useState('');
  const [productQuery, setProductQuery] = useState('');
  const [productCategoryFilter, setProductCategoryFilter] = useState(ALL_CATEGORY_LABEL);
  const [categoryDraft, setCategoryDraft] = useState('');
  const [orderSearch, setOrderSearch] = useState('');
  const [orderStatusFilter, setOrderStatusFilter] = useState('all');
  const [orderPeriodFilter, setOrderPeriodFilter] = useState('today');
  const [customDateFrom, setCustomDateFrom] = useState(toDateInputValue(new Date()));
  const [customDateTo, setCustomDateTo] = useState(toDateInputValue(new Date()));
  const [imageUploadState, setImageUploadState] = useState({
    isUploading: false,
    progress: 0,
    error: '',
    success: '',
  });
  const [noticeForm, setNoticeForm] = useState({
    title: '',
    message: '',
    level: 'normal',
    image: '',
    enabled: true,
    startAt: '',
    endAt: '',
    priority: 0,
  });
  const [editingNoticeId, setEditingNoticeId] = useState(null);
  const [noticeImageUploadState, setNoticeImageUploadState] = useState({
    isUploading: false,
    progress: 0,
    error: '',
    success: '',
  });
  const [logoUploadState, setLogoUploadState] = useState({
    isUploading: false,
    progress: 0,
    error: '',
    success: '',
  });
  const [couponForm, setCouponForm] = useState({ code: '', discount: 10, maxUses: 100, expiresAt: '' });
  const [telegramSettings, setTelegramSettings] = useState({
    enabled: false,
    botToken: '',
    botTokenMasked: '',
    chatId: '',
    chatIdMasked: '',
    hasToken: false,
    notifications: { ...TELEGRAM_NOTIFICATION_DEFAULTS },
    connectionStatus: 'disconnected',
    lastTestAt: '',
    lastError: '',
  });
  const [isTelegramLoading, setIsTelegramLoading] = useState(false);
  const [isTelegramSaving, setIsTelegramSaving] = useState(false);
  const [isTelegramTesting, setIsTelegramTesting] = useState(false);
  const [isTelegramLoaded, setIsTelegramLoaded] = useState(false);
  const [wilayaShippingOptions, setWilayaShippingOptions] = useState([]);
  const [shippingWilayaSearch, setShippingWilayaSearch] = useState('');
  const [isWilayaShippingLoading, setIsWilayaShippingLoading] = useState(false);
  const [wilayaShippingError, setWilayaShippingError] = useState('');
  const isDarkMode = adminTheme === 'dark';

  const formatMoney = (value) => new Intl.NumberFormat('fr-DZ').format(Number(value) || 0) + ' د.ج';
  const formatOrderDate = (value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'تاريخ غير صالح';
    return date.toLocaleString('ar-DZ');
  };

  const orderDateRange = useMemo(
    () =>
      getOrderDateRange(orderPeriodFilter, {
        customStart: customDateFrom,
        customEnd: customDateTo,
      }),
    [orderPeriodFilter, customDateFrom, customDateTo],
  );

  const revenue = useMemo(
    () =>
      orders
        .filter((order) => order.status !== 'cancelled')
        .reduce((sum, order) => sum + (Number(order.totalPrice) || 0), 0),
    [orders],
  );

  const pendingOrdersCount = useMemo(
    () => orders.filter((order) => order.status === 'pending').length,
    [orders],
  );

  const deliveredOrdersCount = useMemo(
    () => orders.filter((order) => order.status === 'delivered').length,
    [orders],
  );

  const lowStockProducts = useMemo(
    () => products.filter((product) => clampStock(product.stock) <= 3),
    [products, clampStock],
  );

  const categoryOptions = useMemo(() => {
    const source = Array.isArray(siteConfig?.productCategories)
      ? siteConfig.productCategories
      : CATEGORIES.filter((entry) => entry !== ALL_CATEGORY_LABEL);

    const normalized = Array.from(
      new Set(source.map((entry) => String(entry || '').trim()).filter(Boolean).filter((entry) => entry !== ALL_CATEGORY_LABEL)),
    );

    if (!normalized.includes(DEFAULT_CATEGORY_NAME)) normalized.push(DEFAULT_CATEGORY_NAME);
    return normalized;
  }, [siteConfig?.productCategories, CATEGORIES]);

  const categoryFilterOptions = useMemo(
    () => [ALL_CATEGORY_LABEL, ...categoryOptions],
    [categoryOptions],
  );

  const customerNotices = useMemo(() => {
    const source = Array.isArray(siteConfig?.customerNotices) ? siteConfig.customerNotices : [];
    return [...source].sort((a, b) => Number(b.priority || 0) - Number(a.priority || 0));
  }, [siteConfig?.customerNotices]);

  const shippingFeesByWilaya = useMemo(() => {
    if (!siteConfig?.shippingFeesByWilaya || typeof siteConfig.shippingFeesByWilaya !== 'object') return {};

    return Object.entries(siteConfig.shippingFeesByWilaya).reduce((acc, [rawCode, rawFee]) => {
      const code = String(rawCode || '').trim().padStart(2, '0');
      if (!code) return acc;
      acc[code] = Math.max(0, Number(rawFee) || 0);
      return acc;
    }, {});
  }, [siteConfig?.shippingFeesByWilaya]);

  const filteredWilayaShippingOptions = useMemo(() => {
    const query = String(shippingWilayaSearch || '').trim().toLowerCase();
    if (!query) return wilayaShippingOptions;

    return wilayaShippingOptions.filter((entry) => {
      const code = String(entry.wilaya_code || '').padStart(2, '0');
      const name = String(entry.wilaya_name || '').toLowerCase();
      return name.includes(query) || code.includes(query);
    });
  }, [shippingWilayaSearch, wilayaShippingOptions]);

  const configuredWilayaShippingCount = useMemo(
    () => Object.keys(shippingFeesByWilaya).length,
    [shippingFeesByWilaya],
  );

  const filteredOrders = useMemo(() => {
    const query = orderSearch.trim().toLowerCase();

    return orders
      .filter((order) => {
        const statusOk = orderStatusFilter === 'all' || order.status === orderStatusFilter;
        const customerWilayaName = (order.customer?.wilaya_name || order.customer?.wilaya || '').toLowerCase();
        const customerCommuneName = (order.customer?.commune_name || order.customer?.commune || order.customer?.city || '').toLowerCase();
        const queryOk =
          !query ||
          String(order.id || '').toLowerCase().includes(query) ||
          order.customer?.name?.toLowerCase().includes(query) ||
          order.customer?.phone?.toLowerCase().includes(query) ||
          customerWilayaName.includes(query) ||
          customerCommuneName.includes(query);

        const dateOk =
          orderPeriodFilter === 'all'
            ? true
            : isWithinDateRange(order.date, orderDateRange);

        return statusOk && queryOk && dateOk;
      })
      .sort((a, b) => new Date(b.date || 0).getTime() - new Date(a.date || 0).getTime());
  }, [orders, orderSearch, orderStatusFilter, orderPeriodFilter, orderDateRange]);

  const filteredOrdersRevenue = useMemo(
    () =>
      filteredOrders
        .filter((order) => order.status !== 'cancelled')
        .reduce((sum, order) => sum + (Number(order.totalPrice) || 0), 0),
    [filteredOrders],
  );

  const filteredOrdersPending = useMemo(
    () => filteredOrders.filter((order) => order.status === 'pending').length,
    [filteredOrders],
  );

  const filteredProducts = useMemo(() => {
    const query = productQuery.trim().toLowerCase();
    return products.filter((product) => {
      const queryOk =
        !query ||
        product.name.toLowerCase().includes(query) ||
        product.category.toLowerCase().includes(query);
      const categoryOk = productCategoryFilter === ALL_CATEGORY_LABEL || product.category === productCategoryFilter;
      return queryOk && categoryOk;
    });
  }, [products, productQuery, productCategoryFilter]);

  const adminCoupons = useMemo(
    () => normalizeCoupons(siteConfig.coupons, siteConfig.couponCode, siteConfig.couponDiscount),
    [siteConfig.coupons, siteConfig.couponCode, siteConfig.couponDiscount, normalizeCoupons],
  );

  const sizeOptions = productForm.variants.sizeType === 'shoes' ? SHOE_SIZES : CLOTHING_SIZES;

  const normalizeFormImages = useCallback((formState) => {
    const raw = [
      ...(Array.isArray(formState?.images) ? formState.images : []),
      String(formState?.image || '').trim(),
    ];

    const unique = Array.from(new Set(raw.map((entry) => String(entry || '').trim()).filter(Boolean)));
    const cover = unique[0] || '';

    return {
      image: cover,
      images: unique,
    };
  }, []);

  const resetProductForm = useCallback(() => {
    setProductForm({
      name: '',
      description: '',
      price: '',
      oldPrice: '',
      category: categoryOptions[0] || DEFAULT_CATEGORY_NAME,
      image: '',
      images: [],
      stock: 10,
      variants: { ...DEFAULT_PRODUCT_VARIANTS },
    });
    setProductImageUrlInput('');
    setEditingProduct(null);
    setImageUploadState({ isUploading: false, progress: 0, error: '', success: '' });
  }, [DEFAULT_PRODUCT_VARIANTS, categoryOptions]);

  const resetNoticeForm = useCallback(() => {
    setNoticeForm({
      title: '',
      message: '',
      level: 'normal',
      image: '',
      enabled: true,
      startAt: '',
      endAt: '',
      priority: 0,
    });
    setEditingNoticeId(null);
    setNoticeImageUploadState({ isUploading: false, progress: 0, error: '', success: '' });
  }, []);

  useEffect(() => {
    if (productCategoryFilter !== ALL_CATEGORY_LABEL && !categoryOptions.includes(productCategoryFilter)) {
      setProductCategoryFilter(ALL_CATEGORY_LABEL);
    }

    if (!categoryOptions.includes(productForm.category)) {
      setProductForm((previous) => ({
        ...previous,
        category: categoryOptions[0] || DEFAULT_CATEGORY_NAME,
      }));
    }
  }, [categoryOptions, productCategoryFilter, productForm.category]);

  const loadWilayaShippingOptions = useCallback(async () => {
    try {
      setIsWilayaShippingLoading(true);
      setWilayaShippingError('');
      const wilayas = await loadAlgeriaWilayas();
      setWilayaShippingOptions(Array.isArray(wilayas) ? wilayas : []);
    } catch (error) {
      setWilayaShippingError(String(error?.message || '\u062a\u0639\u0630\u0631 \u062a\u062d\u0645\u064a\u0644 \u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u0648\u0644\u0627\u064a\u0627\u062a'));
    } finally {
      setIsWilayaShippingLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab !== 'settings' || wilayaShippingOptions.length > 0 || isWilayaShippingLoading) return;
    loadWilayaShippingOptions();
  }, [activeTab, isWilayaShippingLoading, loadWilayaShippingOptions, wilayaShippingOptions.length]);
  const applyTelegramSettings = useCallback((settings) => {
    const source = settings && typeof settings === 'object' ? settings : {};
    setTelegramSettings((previous) => ({
      ...previous,
      enabled: Boolean(source.enabled),
      botToken: '',
      botTokenMasked: String(source.botTokenMasked || ''),
      chatId: String(source.chatId || previous.chatId || ''),
      chatIdMasked: String(source.chatIdMasked || ''),
      hasToken: Boolean(source.hasToken),
      notifications: {
        ...TELEGRAM_NOTIFICATION_DEFAULTS,
        ...(source.notifications || {}),
      },
      connectionStatus: String(source.connectionStatus || 'disconnected'),
      lastTestAt: String(source.lastTestAt || ''),
      lastError: String(source.lastError || ''),
    }));
  }, []);

  const loadTelegramSettings = useCallback(async (silent = false) => {
    try {
      setIsTelegramLoading(true);
      const settings = await fetchTelegramIntegration();
      applyTelegramSettings(settings || {});
      setIsTelegramLoaded(true);
    } catch (error) {
      if (!silent) {
        showToast(String(error?.message || 'تعذر تحميل إعدادات تيليجرام'), 'error');
      }
    } finally {
      setIsTelegramLoading(false);
    }
  }, [applyTelegramSettings, showToast]);

  useEffect(() => {
    if (activeTab !== 'telegram' || isTelegramLoaded) return;
    loadTelegramSettings(true);
  }, [activeTab, isTelegramLoaded, loadTelegramSettings]);

  const handleSaveTelegramSettings = async () => {
    const chatId = String(telegramSettings.chatId || '').trim();
    const token = String(telegramSettings.botToken || '').trim();

    if (!chatId) {
      showToast('أدخل Chat ID أولاً', 'error');
      return;
    }

    if (!token && !telegramSettings.hasToken) {
      showToast('أدخل Bot Token أولاً', 'error');
      return;
    }

    try {
      setIsTelegramSaving(true);
      const settings = await saveTelegramIntegration({
        enabled: telegramSettings.enabled,
        botToken: token,
        chatId,
        notifications: telegramSettings.notifications,
      });
      applyTelegramSettings(settings || {});
      showToast('تم حفظ إعدادات تيليجرام بنجاح', 'success');
    } catch (error) {
      showToast(String(error?.message || 'تعذر حفظ إعدادات تيليجرام'), 'error');
    } finally {
      setIsTelegramSaving(false);
    }
  };

  const handleTestTelegramSettings = async () => {
    try {
      setIsTelegramTesting(true);
      const settings = await testTelegramIntegration({
        botToken: String(telegramSettings.botToken || '').trim(),
        chatId: String(telegramSettings.chatId || '').trim(),
        enabled: telegramSettings.enabled,
        notifications: telegramSettings.notifications,
      });
      applyTelegramSettings(settings || {});
      showToast('تم إرسال رسالة اختبار تيليجرام بنجاح', 'success');
    } catch (error) {
      showToast(String(error?.message || 'فشل اختبار الربط مع تيليجرام'), 'error');
    } finally {
      setIsTelegramTesting(false);
    }
  };

  const notifyAdminAction = async (eventType, payload) => {
    try {
      await sendAdminTelegramNotification(eventType, payload);
    } catch {
      // Keep admin workflow uninterrupted.
    }

    try {
      await logAdminSecurityAction({
        action: payload?.action || eventType || 'admin_action',
        targetType: payload?.entity || eventType || 'admin',
        targetId: String(payload?.entityId || payload?.orderId || ''),
        summary: payload?.label
          ? `Admin action: ${eventType} (${payload.label})`
          : `Admin action: ${eventType}`,
        eventType,
        severity: eventType === 'order_status_changed' ? 'low' : 'medium',
        ...payload,
      });
    } catch {
      // Security telemetry should never interrupt admin workflow.
    }
  };

  const handleSaveProduct = (event) => {
    event.preventDefault();

    const normalizedVariants = normalizeProductVariants(productForm.variants);
    const normalizedMedia = normalizeFormImages(productForm);
    const normalizedCategory = categoryOptions.includes(productForm.category)
      ? productForm.category
      : DEFAULT_CATEGORY_NAME;

    const normalizedProduct = {
      ...productForm,
      name: String(productForm.name || '').trim(),
      description: String(productForm.description || '').trim(),
      category: normalizedCategory,
      image: normalizedMedia.image,
      images: normalizedMedia.images,
      price: Number(productForm.price) || 0,
      oldPrice: Number(productForm.oldPrice) > 0 ? Number(productForm.oldPrice) : 0,
      stock: clampStock(productForm.stock),
      variants: normalizedVariants,
    };

    if (!normalizedProduct.name || !normalizedProduct.image || normalizedProduct.price <= 0) {
      showToast('أدخل بيانات منتج صحيحة', 'error');
      return;
    }

    if (normalizedProduct.oldPrice > 0 && normalizedProduct.oldPrice <= normalizedProduct.price) {
      showToast('السعر قبل الخصم يجب أن يكون أكبر من السعر الحالي', 'error');
      return;
    }

    if (editingProduct) {
      const productId = editingProduct.id;
      setProducts(
        products.map((product) =>
          product.id === productId ? { ...normalizedProduct, id: productId } : product,
        ),
      );
      showToast('تم تعديل المنتج بنجاح');
      void notifyAdminAction('admin_action', {
        action: 'update_product',
        entity: 'product',
        entityId: String(productId),
        label: normalizedProduct.name,
      });
    } else {
      const productId = Date.now();
      setProducts([{ ...normalizedProduct, id: productId }, ...products]);
      showToast('تم نشر المنتج الجديد في المتجر');
      void notifyAdminAction('admin_action', {
        action: 'create_product',
        entity: 'product',
        entityId: String(productId),
        label: normalizedProduct.name,
      });
    }

    setShowProductForm(false);
    resetProductForm();
  };


  const handleAddProductImageByUrl = () => {
    const url = String(productImageUrlInput || '').trim();
    if (!url) return;

    if (!/^https?:\/\//i.test(url)) {
      showToast('أدخل رابط صورة صحيح', 'error');
      return;
    }

    setProductForm((previous) => {
      const nextImages = Array.from(new Set([...(Array.isArray(previous.images) ? previous.images : []), url]));
      return {
        ...previous,
        image: nextImages[0] || url,
        images: nextImages,
      };
    });

    setProductImageUrlInput('');
  };

  const handleSetPrimaryProductImage = (imageIndex) => {
    setProductForm((previous) => {
      const images = Array.isArray(previous.images) ? [...previous.images] : [];
      if (!images[imageIndex]) return previous;
      const [selected] = images.splice(imageIndex, 1);
      const nextImages = [selected, ...images];
      return {
        ...previous,
        image: nextImages[0],
        images: nextImages,
      };
    });
  };

  const handleMoveProductImage = (imageIndex, direction) => {
    setProductForm((previous) => {
      const images = Array.isArray(previous.images) ? [...previous.images] : [];
      const nextIndex = imageIndex + direction;
      if (!images[imageIndex] || nextIndex < 0 || nextIndex >= images.length) return previous;
      const temp = images[imageIndex];
      images[imageIndex] = images[nextIndex];
      images[nextIndex] = temp;
      return {
        ...previous,
        image: images[0] || '',
        images,
      };
    });
  };

  const handleRemoveProductImage = (imageIndex) => {
    setProductForm((previous) => {
      const images = (Array.isArray(previous.images) ? previous.images : []).filter((_, idx) => idx !== imageIndex);
      return {
        ...previous,
        image: images[0] || '',
        images,
      };
    });
  };

  const handleAddCategory = () => {
    const value = String(categoryDraft || '').trim();
    if (!value) return;

    if (value === ALL_CATEGORY_LABEL) {
      showToast('لا يمكن استخدام تصنيف الكل', 'error');
      return;
    }

    if (categoryOptions.includes(value)) {
      showToast('التصنيف موجود مسبقًا', 'error');
      return;
    }

    setSiteConfig({
      ...siteConfig,
      productCategories: [...categoryOptions, value],
    });
    setCategoryDraft('');
    showToast('تم إضافة التصنيف', 'success');
  };

  const handleRenameCategory = (oldName) => {
    if (!oldName || oldName === DEFAULT_CATEGORY_NAME) {
      showToast('هذا التصنيف محمي', 'error');
      return;
    }

    const proposed = window.prompt('اسم التصنيف الجديد', oldName);
    const nextName = String(proposed || '').trim();
    if (!nextName || nextName === oldName) return;

    if (nextName === ALL_CATEGORY_LABEL || categoryOptions.includes(nextName)) {
      showToast('الاسم غير متاح', 'error');
      return;
    }

    const nextCategories = categoryOptions.map((entry) => (entry === oldName ? nextName : entry));
    setSiteConfig({
      ...siteConfig,
      productCategories: nextCategories,
    });

    setProducts(
      products.map((product) =>
        product.category === oldName ? { ...product, category: nextName } : product,
      ),
    );

    showToast('تم تعديل اسم التصنيف', 'success');
  };

  const handleDeleteCategory = (categoryName) => {
    if (!categoryName || categoryName === DEFAULT_CATEGORY_NAME) {
      showToast('التصنيف أخرى محمي ولا يمكن حذفه', 'error');
      return;
    }

    if (!window.confirm('سيتم نقل منتجات هذا التصنيف إلى أخرى. متابعة؟')) return;

    const nextCategories = categoryOptions.filter((entry) => entry !== categoryName);
    if (!nextCategories.includes(DEFAULT_CATEGORY_NAME)) nextCategories.push(DEFAULT_CATEGORY_NAME);

    setSiteConfig({
      ...siteConfig,
      productCategories: nextCategories,
    });

    setProducts(
      products.map((product) =>
        product.category === categoryName ? { ...product, category: DEFAULT_CATEGORY_NAME } : product,
      ),
    );

    showToast('تم حذف التصنيف ونقل المنتجات إلى أخرى', 'success');
  };

  const handleSaveNotice = (event) => {
    event.preventDefault();

    const title = String(noticeForm.title || '').trim();
    const message = String(noticeForm.message || '').trim();
    if (!title && !message) {
      showToast('أدخل عنوان أو نص الإشعار', 'error');
      return;
    }

    const level = NOTICE_LEVEL_OPTIONS.some((entry) => entry.value === noticeForm.level) ? noticeForm.level : 'normal';
    const nowIso = new Date().toISOString();
    const payload = {
      id: editingNoticeId || ('notice-' + String(Date.now())),
      title,
      message,
      level,
      image: String(noticeForm.image || '').trim(),
      enabled: Boolean(noticeForm.enabled),
      startAt: noticeForm.startAt ? new Date(noticeForm.startAt).toISOString() : '',
      endAt: noticeForm.endAt ? new Date(noticeForm.endAt).toISOString() : '',
      priority: Number(noticeForm.priority) || 0,
      createdAt: editingNoticeId
        ? (customerNotices.find((entry) => entry.id === editingNoticeId)?.createdAt || nowIso)
        : nowIso,
      updatedAt: nowIso,
    };

    const nextNotices = editingNoticeId
      ? customerNotices.map((entry) => (entry.id === editingNoticeId ? payload : entry))
      : [payload, ...customerNotices];

    setSiteConfig({
      ...siteConfig,
      customerNotices: nextNotices,
    });

    showToast(editingNoticeId ? 'تم تحديث إشعار الزبائن' : 'تم إنشاء إشعار جديد', 'success');
    resetNoticeForm();
  };

  const handleEditNotice = (notice) => {
    setEditingNoticeId(notice.id);
    const toDateValue = (value) => {
      if (!value) return '';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return '';
      return date.toISOString().slice(0, 16);
    };

    setNoticeForm({
      title: String(notice.title || ''),
      message: String(notice.message || ''),
      level: String(notice.level || 'normal'),
      image: String(notice.image || ''),
      enabled: Boolean(notice.enabled),
      startAt: toDateValue(notice.startAt),
      endAt: toDateValue(notice.endAt),
      priority: Number(notice.priority) || 0,
    });
  };

  const handleDeleteNotice = (noticeId) => {
    if (!window.confirm('حذف هذا الإشعار؟')) return;
    setSiteConfig({
      ...siteConfig,
      customerNotices: customerNotices.filter((entry) => entry.id !== noticeId),
    });
    if (editingNoticeId === noticeId) resetNoticeForm();
    showToast('تم حذف الإشعار', 'success');
  };

  const handleToggleNoticeEnabled = (noticeId) => {
    const nextNotices = customerNotices.map((entry) =>
      entry.id === noticeId
        ? { ...entry, enabled: !entry.enabled, updatedAt: new Date().toISOString() }
        : entry,
    );

    setSiteConfig({
      ...siteConfig,
      customerNotices: nextNotices,
    });
  };

  const handleUploadNoticeImage = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const validation = validateImageFile(file, { maxSizeMb: 8 });
    if (!validation.ok) {
      setNoticeImageUploadState({ isUploading: false, progress: 0, error: validation.message, success: '' });
      showToast(validation.message, 'error');
      event.target.value = '';
      return;
    }

    try {
      setNoticeImageUploadState({ isUploading: true, progress: 0, error: '', success: '' });
      const imageUrl = await uploadProductImage(file, {
        maxSizeMb: 8,
        onProgress: (progress) =>
          setNoticeImageUploadState((previous) => ({
            ...previous,
            progress,
          })),
      });

      setNoticeForm((previous) => ({ ...previous, image: imageUrl }));
      setNoticeImageUploadState({ isUploading: false, progress: 100, error: '', success: 'تم رفع صورة الإشعار بنجاح.' });
      showToast('تم رفع صورة الإشعار', 'success');
    } catch (error) {
      const message = String(error?.message || 'فشل رفع صورة الإشعار');
      setNoticeImageUploadState({ isUploading: false, progress: 0, error: message, success: '' });
      showToast(message, 'error');
    } finally {
      event.target.value = '';
    }
  };
  const handleUploadStoreLogo = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const validation = validateImageFile(file, { maxSizeMb: 6 });
    if (!validation.ok) {
      setLogoUploadState({ isUploading: false, progress: 0, error: validation.message, success: '' });
      showToast(validation.message, 'error');
      event.target.value = '';
      return;
    }

    try {
      setLogoUploadState({ isUploading: true, progress: 0, error: '', success: '' });
      const imageUrl = await uploadProductImage(file, {
        maxSizeMb: 6,
        onProgress: (progress) =>
          setLogoUploadState((previous) => ({
            ...previous,
            progress,
          })),
      });

      setSiteConfig((previous) => ({
        ...previous,
        logoUrl: imageUrl,
      }));

      setLogoUploadState({
        isUploading: false,
        progress: 100,
        error: '',
        success: 'تم رفع شعار المتجر بنجاح.',
      });
      showToast('تم تحديث شعار المتجر', 'success');
    } catch (error) {
      const message = String(error?.message || 'فشل رفع شعار المتجر');
      setLogoUploadState({ isUploading: false, progress: 0, error: message, success: '' });
      showToast(message, 'error');
    } finally {
      event.target.value = '';
    }
  };

  const handleShippingFeeChange = (wilayaCode, nextValue) => {
    const normalizedCode = String(wilayaCode || '').trim().padStart(2, '0');
    if (!normalizedCode) return;

    const rawValue = String(nextValue ?? '').trim();

    setSiteConfig((previous) => {
      const current = previous?.shippingFeesByWilaya && typeof previous.shippingFeesByWilaya === 'object'
        ? previous.shippingFeesByWilaya
        : {};

      const next = { ...current };

      if (rawValue === '') {
        delete next[normalizedCode];
      } else {
        next[normalizedCode] = Math.max(0, Number(rawValue) || 0);
      }

      return {
        ...previous,
        shippingFeesByWilaya: next,
      };
    });
  };

  const handleResetShippingFees = () => {
    if (configuredWilayaShippingCount === 0) return;
    if (!window.confirm('\u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0643\u0644 \u0623\u0633\u0639\u0627\u0631 \u0627\u0644\u062a\u0648\u0635\u064a\u0644 \u0644\u0644\u0648\u0644\u0627\u064a\u0627\u062a \u0625\u0644\u0649 \u0627\u0644\u0642\u064a\u0645\u0629 \u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a\u0629 0 \u062f.\u062c\u061f')) return;

    setSiteConfig((previous) => ({
      ...previous,
      shippingFeesByWilaya: {},
    }));

    showToast('\u062a\u0645 \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0623\u0633\u0639\u0627\u0631 \u0627\u0644\u062a\u0648\u0635\u064a\u0644 \u0644\u062c\u0645\u064a\u0639 \u0627\u0644\u0648\u0644\u0627\u064a\u0627\u062a', 'success');
  };

  const handleDeleteProduct = (id) => {
    if (window.confirm('هل تريد حذف هذا المنتج من المتجر؟')) {
      const product = products.find((entry) => entry.id === id);
      setProducts(products.filter((entry) => entry.id !== id));
      showToast('تم حذف المنتج', 'error');
      void notifyAdminAction('admin_action', {
        action: 'delete_product',
        entity: 'product',
        entityId: String(id),
        label: product?.name || '',
      });
    }
  };


  const handleUploadProductImage = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const validation = validateImageFile(file, { maxSizeMb: 8 });
    if (!validation.ok) {
      setImageUploadState({
        isUploading: false,
        progress: 0,
        error: validation.message,
        success: '',
      });
      showToast(validation.message, 'error');
      event.target.value = '';
      return;
    }

    try {
      setImageUploadState({
        isUploading: true,
        progress: 0,
        error: '',
        success: '',
      });

      const imageUrl = await uploadProductImage(file, {
        maxSizeMb: 8,
        onProgress: (progress) =>
          setImageUploadState((previous) => ({
            ...previous,
            progress,
          })),
      });

      setProductForm((previous) => {
        const nextImages = Array.from(new Set([...(Array.isArray(previous.images) ? previous.images : []), imageUrl]));
        return {
          ...previous,
          image: nextImages[0] || imageUrl,
          images: nextImages,
        };
      });
      setImageUploadState({
        isUploading: false,
        progress: 100,
        error: '',
        success: 'تم رفع الصورة بنجاح عبر ImgBB.',
      });
      showToast('تم رفع الصورة عبر ImgBB بنجاح', 'success');
    } catch (error) {
      const message = String(error?.message || 'فشل رفع الصورة. حاول مرة أخرى.');
      setImageUploadState({
        isUploading: false,
        progress: 0,
        error: message,
        success: '',
      });
      showToast(message, 'error');
    } finally {
      event.target.value = '';
    }
  };

  const handleCreateCoupon = (event) => {
    event.preventDefault();

    const code = normalizeCouponCode(couponForm.code);
    const discount = clampDiscount(couponForm.discount);
    const maxUses = clampUses(couponForm.maxUses);
    const expiresAt = couponForm.expiresAt ? new Date(couponForm.expiresAt).toISOString() : '';

    if (!code || discount <= 0) {
      showToast('أدخل كود كوبون ونسبة خصم صحيحة', 'error');
      return;
    }

    if (adminCoupons.some((coupon) => normalizeCouponCode(coupon.code) === code)) {
      showToast('هذا الكود موجود مسبقاً', 'error');
      return;
    }

    setSiteConfig({
      ...siteConfig,
      coupons: [
        {
          id: String(Date.now()) + '-' + code,
          code,
          discount,
          maxUses,
          usedCount: 0,
          expiresAt,
        },
        ...adminCoupons,
      ],
    });

    setCouponForm({ code: '', discount: 10, maxUses: 100, expiresAt: '' });
    showToast('تم إنشاء الكوبون بنجاح', 'success');
  };

  const handleDeleteCoupon = (couponId) => {
    setSiteConfig({
      ...siteConfig,
      coupons: adminCoupons.filter((coupon) => coupon.id !== couponId),
    });
    showToast('تم حذف الكوبون', 'error');
  };

  const handleOrderStatusChange = (orderId, nextStatus) => {
    const orderBefore = orders.find((order) => order.id === orderId);
    setOrders(
      orders.map((order) => (order.id === orderId ? { ...order, status: nextStatus } : order)),
    );
    showToast('تم تحديث حالة الطلب');

    void notifyAdminAction('order_status_changed', {
      orderId: String(orderId),
      previousStatus: orderBefore?.status || '',
      nextStatus,
      customerName: orderBefore?.customer?.name || '',
    });
  };

  return (
    <Motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={PAGE_TRANSITION}
      className={`admin-cms ${isDarkMode ? 'admin-theme-dark' : 'admin-theme-light bg-gradient-to-br from-slate-100 via-white to-emerald-50/60'} pb-24 md:pb-10 min-h-screen`}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800;900&display=swap');
        body { font-family: 'Tajawal', sans-serif; background-color: ${isDarkMode ? '#020617' : '#f8fafc'}; margin: 0; padding: 0; }
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
        @keyframes skeleton-shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        .skeleton-shimmer {
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.55), transparent);
          animation: skeleton-shimmer 1.2s infinite;
        }
        .admin-cms {
          --admin-surface: #ffffff;
          --admin-surface-alt: #f8fafc;
          --admin-text: #0f172a;
          --admin-muted: #475569;
          --admin-soft-muted: #64748b;
          --admin-border: #dbe3ee;
          --admin-input: #ffffff;
          --admin-input-border: #d1d9e6;
          --admin-input-placeholder: #94a3b8;
          --admin-primary: #0f172a;
          --admin-primary-hover: #1e293b;
          --admin-focus: #10b981;
        }
        .admin-theme-light {
          color: var(--admin-text);
        }
        .admin-theme-dark {
          --admin-surface: #0f172a;
          --admin-surface-alt: #111c31;
          --admin-text: #f8fafc;
          --admin-muted: #dbe4f0;
          --admin-soft-muted: #b8c4d7;
          --admin-border: #334155;
          --admin-input: #0b1220;
          --admin-input-border: #334155;
          --admin-input-placeholder: #94a3b8;
          --admin-primary: #1e293b;
          --admin-primary-hover: #334155;
          --admin-focus: #34d399;
          background: radial-gradient(circle at 20% 0%, #0f172a 0%, #020617 45%, #020617 100%);
          color: var(--admin-text);
        }
        .admin-theme-dark .admin-soft {
          background: var(--admin-surface);
          border-color: var(--admin-border);
        }
        .admin-theme-dark .admin-sidebar {
          background: rgba(15, 23, 42, 0.92) !important;
          border-color: var(--admin-border) !important;
        }
        .admin-theme-dark .admin-sidebar .nav-btn--inactive {
          color: var(--admin-muted) !important;
        }
        .admin-theme-dark .admin-sidebar .nav-btn--inactive:hover {
          background: rgba(51, 65, 85, 0.55) !important;
        }
        .admin-theme-dark .bg-white,
        .admin-theme-dark .bg-slate-50,
        .admin-theme-dark .bg-gray-50,
        .admin-theme-dark .bg-slate-100,
        .admin-theme-dark .bg-gray-100 {
          background-color: var(--admin-surface) !important;
        }
        .admin-theme-dark .text-slate-900,
        .admin-theme-dark .text-slate-800,
        .admin-theme-dark .text-gray-900,
        .admin-theme-dark .text-gray-800 {
          color: var(--admin-text) !important;
        }
        .admin-theme-dark .text-slate-700,
        .admin-theme-dark .text-slate-600,
        .admin-theme-dark .text-gray-700,
        .admin-theme-dark .text-gray-600,
        .admin-theme-dark .text-gray-500,
        .admin-theme-dark .text-slate-500 {
          color: var(--admin-muted) !important;
        }
        .admin-theme-dark .text-slate-400,
        .admin-theme-dark .text-gray-400 {
          color: var(--admin-soft-muted) !important;
        }
        .admin-theme-dark .border-gray-100,
        .admin-theme-dark .border-gray-200,
        .admin-theme-dark .border-gray-300,
        .admin-theme-dark .border-slate-100,
        .admin-theme-dark .border-slate-200,
        .admin-theme-dark .border-slate-300 {
          border-color: var(--admin-border) !important;
        }
        .admin-theme-dark input,
        .admin-theme-dark select,
        .admin-theme-dark textarea {
          background: var(--admin-input) !important;
          color: var(--admin-text) !important;
          border-color: var(--admin-input-border) !important;
        }
        .admin-theme-dark input::placeholder,
        .admin-theme-dark textarea::placeholder {
          color: var(--admin-input-placeholder) !important;
        }
        .admin-theme-dark option {
          background: #0f172a;
          color: #f8fafc;
        }
        .admin-theme-dark .bg-slate-900 {
          background-color: var(--admin-primary) !important;
        }
        .admin-theme-dark [class*='hover:bg-slate-800']:hover,
        .admin-theme-dark [class*='hover:bg-slate-900']:hover {
          background-color: var(--admin-primary-hover) !important;
        }
        .admin-theme-dark [class*='hover:bg-slate-50']:hover,
        .admin-theme-dark [class*='hover:bg-slate-100']:hover {
          background-color: rgba(51, 65, 85, 0.45) !important;
        }
        .admin-theme-dark .bg-emerald-50 {
          background-color: rgba(16, 185, 129, 0.18) !important;
        }
        .admin-theme-dark .bg-amber-50,
        .admin-theme-dark .bg-orange-50 {
          background-color: rgba(245, 158, 11, 0.2) !important;
        }
        .admin-theme-dark .bg-blue-50 {
          background-color: rgba(59, 130, 246, 0.2) !important;
        }
        .admin-theme-dark .bg-red-50 {
          background-color: rgba(239, 68, 68, 0.2) !important;
        }
        .admin-theme-dark .text-emerald-700,
        .admin-theme-dark .text-emerald-600 {
          color: #6ee7b7 !important;
        }
        .admin-theme-dark .text-blue-700,
        .admin-theme-dark .text-blue-600 {
          color: #93c5fd !important;
        }
        .admin-theme-dark .text-amber-800,
        .admin-theme-dark .text-amber-700,
        .admin-theme-dark .text-orange-700,
        .admin-theme-dark .text-orange-600 {
          color: #fcd34d !important;
        }
        .admin-theme-dark .text-red-700,
        .admin-theme-dark .text-red-600 {
          color: #fca5a5 !important;
        }
        .admin-theme-dark .border-emerald-200 {
          border-color: rgba(16, 185, 129, 0.45) !important;
        }
        .admin-theme-dark .border-amber-200,
        .admin-theme-dark .border-orange-200 {
          border-color: rgba(245, 158, 11, 0.45) !important;
        }
        .admin-theme-dark .border-blue-200 {
          border-color: rgba(59, 130, 246, 0.45) !important;
        }
        .admin-theme-dark .border-red-200 {
          border-color: rgba(239, 68, 68, 0.45) !important;
        }
        .admin-cms button:disabled {
          opacity: 0.58;
          cursor: not-allowed;
        }
        .admin-cms button:focus-visible,
        .admin-cms input:focus-visible,
        .admin-cms select:focus-visible,
        .admin-cms textarea:focus-visible {
          outline: 2px solid var(--admin-focus);
          outline-offset: 2px;
        }
        .admin-sidebar button {
          min-height: 44px;
        }
        @media (max-width: 1024px) {
          .admin-sidebar {
            position: sticky;
            top: 84px;
            z-index: 25;
          }
        }
      `}</style>
      <header className={`sticky top-0 z-40 border-b backdrop-blur-xl ${isDarkMode ? "border-slate-700/70 bg-slate-900/80" : "border-slate-200/70 bg-white/90"}`}>
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-4 flex flex-col md:flex-row justify-between md:items-center gap-3">
          <div>
            <h1 className="text-xl md:text-2xl font-black admin-title flex items-center gap-2">
              <ShieldCheck className="text-emerald-600" /> لوحة التحكم المركزية
            </h1>
            <p className={`text-xs font-bold mt-1 ${isDarkMode ? "text-slate-300" : "text-slate-500"}`} dir="ltr">{adminUser?.email || 'admin'}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`px-3 py-1.5 rounded-full text-xs font-bold border ${
                siteConfig.isOnline
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-orange-50 text-orange-700 border-orange-200'
              }`}
            >
              {siteConfig.isOnline ? 'المتجر مفتوح' : 'وضع الصيانة'}
            </span>
            <span
              className={`px-3 py-1.5 rounded-full text-xs font-bold border ${
                syncStatus === 'online'
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : syncStatus === 'syncing'
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}
            >
              {syncStatus === 'online' ? 'Firebase متصل' : syncStatus === 'syncing' ? 'جاري المزامنة' : 'وضع محلي'}
            </span>
            <div className={`inline-flex items-center rounded-xl border p-1 ${isDarkMode ? 'admin-soft' : 'bg-white border-slate-200'}`}>
              <button
                onClick={() => setAdminTheme('dark')}
                className={`px-3 py-1.5 rounded-lg text-xs font-black inline-flex items-center gap-1 transition ${
                  isDarkMode ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <MoonStar size={14} /> وضع ليل
              </button>
              <button
                onClick={() => setAdminTheme('light')}
                className={`px-3 py-1.5 rounded-lg text-xs font-black inline-flex items-center gap-1 transition ${
                  !isDarkMode ? 'bg-emerald-500 text-white' : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <SunMedium size={14} /> وضع صباح
              </button>
            </div>
            <button
              onClick={() => onLogout()}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 text-white text-sm font-black hover:bg-slate-800 transition"
              title="خروج"
            >
              <LogOut size={16} /> خروج
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto flex flex-col lg:flex-row mt-6 md:mt-8 px-4 md:px-6 gap-6 md:gap-8">
        <aside className="lg:w-72 shrink-0">
          <div className={`admin-sidebar rounded-3xl border backdrop-blur p-3 shadow-sm ${isDarkMode ? 'border-slate-700 bg-slate-900/95' : 'border-slate-200 bg-white/95'}`}>
            <div className="rounded-2xl bg-gradient-to-l from-emerald-500 to-teal-500 text-white p-4 mb-3">
              <div className="flex items-center gap-2 font-black text-sm">
                <Sparkles size={16} /> Dashboard Modern
              </div>
              <p className="text-[11px] text-emerald-50 mt-1">تنقل سريع بين الأقسام الأساسية</p>
            </div>

            <div className="flex lg:flex-col gap-2 overflow-x-auto no-scrollbar pb-1 lg:pb-0">
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`flex items-center gap-3 px-4 py-3 rounded-2xl whitespace-nowrap transition-colors font-bold ${
                  activeTab === 'dashboard' ? (isDarkMode ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-white shadow-lg shadow-slate-900/10') : (isDarkMode ? 'nav-btn--inactive text-slate-200 hover:bg-slate-800/70' : 'nav-btn--inactive text-slate-600 hover:bg-slate-100')
                }`}
              >
                <LayoutDashboard size={18} /> نظرة عامة
              </button>
              <button
                onClick={() => setActiveTab('orders')}
                className={`flex items-center gap-3 px-4 py-3 rounded-2xl whitespace-nowrap transition-colors font-bold ${
                  activeTab === 'orders' ? (isDarkMode ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-white shadow-lg shadow-slate-900/10') : (isDarkMode ? 'nav-btn--inactive text-slate-200 hover:bg-slate-800/70' : 'nav-btn--inactive text-slate-600 hover:bg-slate-100')
                }`}
              >
                <ShoppingCart size={18} /> الطلبات
              </button>
              <button
                onClick={() => setActiveTab('products')}
                className={`flex items-center gap-3 px-4 py-3 rounded-2xl whitespace-nowrap transition-colors font-bold ${
                  activeTab === 'products' ? (isDarkMode ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-white shadow-lg shadow-slate-900/10') : (isDarkMode ? 'nav-btn--inactive text-slate-200 hover:bg-slate-800/70' : 'nav-btn--inactive text-slate-600 hover:bg-slate-100')
                }`}
              >
                <Store size={18} /> المنتجات
              </button>
              <button
                onClick={() => setActiveTab('marketing')}
                className={`flex items-center gap-3 px-4 py-3 rounded-2xl whitespace-nowrap transition-colors font-bold ${
                  activeTab === 'marketing' ? (isDarkMode ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-white shadow-lg shadow-slate-900/10') : (isDarkMode ? 'nav-btn--inactive text-slate-200 hover:bg-slate-800/70' : 'nav-btn--inactive text-slate-600 hover:bg-slate-100')
                }`}
              >
                <Megaphone size={18} /> التسويق
              </button>
              <button
                onClick={() => setActiveTab('telegram')}
                className={
                  'flex items-center gap-3 px-4 py-3 rounded-2xl whitespace-nowrap transition-colors font-bold ' +
                  (activeTab === 'telegram'
                    ? (isDarkMode ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-white shadow-lg shadow-slate-900/10')
                    : (isDarkMode ? 'nav-btn--inactive text-slate-200 hover:bg-slate-800/70' : 'nav-btn--inactive text-slate-600 hover:bg-slate-100'))
                }
              >
                <MessageCircle size={18} /> ربط تيليجرام
              </button>
              <button
                onClick={() => setActiveTab('settings')}
                className={`flex items-center gap-3 px-4 py-3 rounded-2xl whitespace-nowrap transition-colors font-bold ${
                  activeTab === 'settings' ? (isDarkMode ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-white shadow-lg shadow-slate-900/10') : (isDarkMode ? 'nav-btn--inactive text-slate-200 hover:bg-slate-800/70' : 'nav-btn--inactive text-slate-600 hover:bg-slate-100')
                }`}
              >
                <Settings size={18} /> الإعدادات
              </button>
              <button
                onClick={() => setActiveTab('security')}
                className={`flex items-center gap-3 px-4 py-3 rounded-2xl whitespace-nowrap transition-colors font-bold ${
                  activeTab === 'security' ? (isDarkMode ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20' : 'bg-slate-900 text-white shadow-lg shadow-slate-900/10') : (isDarkMode ? 'nav-btn--inactive text-slate-200 hover:bg-slate-800/70' : 'nav-btn--inactive text-slate-600 hover:bg-slate-100')
                }`}
              >
                <ShieldAlert size={18} /> مراقبة الموقع
              </button>
            </div>
          </div>
        </aside>

        <div className="flex-1 w-full overflow-hidden">
          {activeTab === 'dashboard' && (
            <div className="space-y-6 animate-in fade-in">
              <h2 className="text-2xl font-black text-slate-900 mb-6">الإحصائيات الرئيسية</h2>

              <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                <div className="bg-slate-50 p-5 rounded-3xl border border-gray-100">
                  <div className="w-10 h-10 bg-blue-100 text-blue-600 rounded-xl flex items-center justify-center mb-3">
                    <Package size={20} />
                  </div>
                  <p className="text-sm font-bold text-gray-500 mb-1">الطلبات</p>
                  <p className="text-2xl font-black">{orders.length}</p>
                </div>

                <div className="bg-slate-50 p-5 rounded-3xl border border-gray-100">
                  <div className="w-10 h-10 bg-amber-100 text-amber-700 rounded-xl flex items-center justify-center mb-3">
                    <ShoppingCart size={20} />
                  </div>
                  <p className="text-sm font-bold text-gray-500 mb-1">قيد المعالجة</p>
                  <p className="text-2xl font-black">{pendingOrdersCount}</p>
                </div>

                <div className="bg-slate-50 p-5 rounded-3xl border border-gray-100">
                  <div className="w-10 h-10 bg-emerald-100 text-emerald-700 rounded-xl flex items-center justify-center mb-3">
                    <CheckCircle size={20} />
                  </div>
                  <p className="text-sm font-bold text-gray-500 mb-1">تم التسليم</p>
                  <p className="text-2xl font-black">{deliveredOrdersCount}</p>
                </div>

                <div className="bg-slate-50 p-5 rounded-3xl border border-gray-100">
                  <div className="w-10 h-10 bg-emerald-100 text-emerald-600 rounded-xl flex items-center justify-center mb-3">
                    <CreditCard size={20} />
                  </div>
                  <p className="text-sm font-bold text-gray-500 mb-1">الإيرادات</p>
                  <p className="text-xl font-black text-emerald-600">{revenue} د.ج</p>
                </div>

                <div className="bg-slate-50 p-5 rounded-3xl border border-gray-100">
                  <div className="w-10 h-10 bg-orange-100 text-orange-600 rounded-xl flex items-center justify-center mb-3">
                    <AlertTriangle size={20} />
                  </div>
                  <p className="text-sm font-bold text-gray-500 mb-1">مخزون منخفض</p>
                  <p className="text-2xl font-black">{lowStockProducts.length}</p>
                </div>
              </div>
              <div className="mt-8 rounded-2xl border border-gray-200 bg-white p-6 text-center">
                <p className="font-black text-slate-900 mb-2">عرض الطلبات أصبح في قسم مستقل</p>
                <p className="text-sm font-bold text-gray-500 mb-4">اضغط على تبويب "الطلبات" لإدارة جميع الطلبات بالتفصيل.</p>
                <button
                  onClick={() => setActiveTab('orders')}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-900 text-white font-black"
                >
                  <ShoppingCart size={16} /> فتح قسم الطلبات
                </button>
              </div>
            </div>
          )}

          {activeTab === 'orders' && (
            <div className="space-y-6 animate-in fade-in">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                <h2 className="text-2xl font-black text-slate-900 flex items-center gap-2"><CalendarDays size={22} />{'إدارة الطلبيات'}</h2>
                <div className="text-sm font-bold text-gray-500">{filteredOrders.length} طلب</div>
              </div>

              <div className="flex gap-2 overflow-x-auto no-scrollbar pb-1">
                {ORDER_PERIOD_OPTIONS.map((option) => (
                  <button
                    key={option.key}
                    type="button"
                    onClick={() => setOrderPeriodFilter(option.key)}
                    className={
                      'px-3 py-2 rounded-xl text-xs font-black whitespace-nowrap border transition ' +
                      (orderPeriodFilter === option.key
                        ? 'bg-slate-900 text-white border-slate-900'
                        : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50')
                    }
                  >
                    {option.label}
                  </button>
                ))}
              </div>

              {orderPeriodFilter === 'custom' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-bold text-gray-500 mb-1">{'من تاريخ'}</label>
                    <input
                      type="date"
                      value={customDateFrom}
                      onChange={(event) => setCustomDateFrom(event.target.value)}
                      className="w-full bg-white border border-gray-200 rounded-xl px-4 py-3 font-bold outline-none focus:ring-2 focus:ring-slate-900/10"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-bold text-gray-500 mb-1">{'إلى تاريخ'}</label>
                    <input
                      type="date"
                      value={customDateTo}
                      onChange={(event) => setCustomDateTo(event.target.value)}
                      className="w-full bg-white border border-gray-200 rounded-xl px-4 py-3 font-bold outline-none focus:ring-2 focus:ring-slate-900/10"
                    />
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="md:col-span-2 relative">
                  <Search size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    value={orderSearch}
                    onChange={(event) => setOrderSearch(event.target.value)}
                    placeholder={'بحث بالاسم أو الهاتف أو الولاية'}
                    className="w-full bg-white border border-gray-200 rounded-xl pr-9 pl-4 py-3 font-bold outline-none focus:ring-2 focus:ring-slate-900/10"
                  />
                </div>
                <div className="relative">
                  <Filter size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <select
                    value={orderStatusFilter}
                    onChange={(event) => setOrderStatusFilter(event.target.value)}
                    className="w-full bg-white border border-gray-200 rounded-xl pr-9 pl-3 py-3 font-bold outline-none focus:ring-2 focus:ring-slate-900/10"
                  >
                    <option value="all">{'كل الحالات'}</option>
                    {ORDER_STATUSES.map((status) => (
                      <option value={status.key} key={status.key}>
                        {status.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs font-bold text-slate-500">{'عدد الطلبيات'}</p>
                  <p className="text-xl font-black text-slate-900">{filteredOrders.length}</p>
                </div>
                <div className="rounded-xl border border-amber-200 bg-amber-50 p-3">
                  <p className="text-xs font-bold text-amber-700">{'قيد المعالجة'}</p>
                  <p className="text-xl font-black text-amber-800">{filteredOrdersPending}</p>
                </div>
                <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-3 col-span-2">
                  <p className="text-xs font-bold text-emerald-700">{'قيمة الطلبيات'}</p>
                  <p className="text-xl font-black text-emerald-800">{formatMoney(filteredOrdersRevenue)}</p>
                </div>
              </div>

              {filteredOrders.length === 0 ? (
                <div className="text-center py-12 bg-gray-50 rounded-2xl border border-gray-100 text-gray-400 font-bold">
                  لا توجد نتائج مطابقة
                </div>
              ) : (
                <div className="space-y-4">
                  {filteredOrders.map((order) => (
                    <div key={order.id} className="bg-white border border-gray-200 rounded-2xl p-5 space-y-4">
                      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                        <div>
                          <p className="font-black text-slate-900 text-lg">{order.customer.name}</p>
                          <p className="text-sm text-gray-500 font-bold">{order.customer.wilaya_name || order.customer.wilaya} • {order.customer.commune_name || order.customer.commune || order.customer.city}</p>
                          <p className="text-sm text-gray-500 font-bold">{order.customer.phone}</p>
                          <p className="text-xs text-gray-400 mt-1">#{String(order.id).slice(-6)} • {formatOrderDate(order.date)}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <select
                            value={order.status}
                            onChange={(event) => handleOrderStatusChange(order.id, event.target.value)}
                            className="bg-gray-50 border border-gray-200 rounded-xl px-3 py-2 font-bold outline-none"
                          >
                            {ORDER_STATUSES.map((status) => (
                              <option key={status.key} value={status.key}>
                                {status.label}
                              </option>
                            ))}
                          </select>
                          <OrderStatusPill status={order.status} getOrderStatusMeta={getOrderStatusMeta} />
                        </div>
                      </div>

                      <div className="bg-gray-50 border border-gray-100 rounded-xl p-3">
                        <p className="text-xs font-black text-gray-500 mb-2">المنتجات</p>
                        <div className="space-y-1">
                          {order.items.map((item) => (
                            <div key={`${order.id}-${item.cartKey || buildCartItemKey(item)}`} className="flex items-center justify-between text-sm font-bold text-slate-700">
                              <span>
                                {item.name}
                                {(item.selectedSize || item.selectedColor) && (
                                  <span className="text-[10px] text-slate-500 mr-2">
                                    {item.selectedSize ? 'مقاس: ' + item.selectedSize : ''}
                                    {item.selectedSize && item.selectedColor ? ' | ' : ''}
                                    {item.selectedColor ? 'لون: ' + item.selectedColor : ''}
                                  </span>
                                )}
                              </span>
                              <span>x{item.qty}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-4 text-sm font-bold">
                        <span className="text-gray-500">فرعي: {order.subtotal} د.ج</span>
                        {order.discount > 0 && <span className="text-emerald-600">خصم: -{order.discount} د.ج</span>}
                        {order.couponCode && <span className="text-gray-500" dir="ltr">{order.couponCode}</span>}
                        <span className="text-slate-900">الإجمالي: {order.totalPrice} د.ج</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
          {activeTab === 'products' && (
            <div className="space-y-6 animate-in fade-in">
              <div className="flex flex-col md:flex-row justify-between md:items-center gap-3">
                <h2 className="text-2xl font-black text-slate-900">إدارة المنتجات والمخزون</h2>
                <button
                  onClick={() => {
                    resetProductForm();
                    setShowProductForm(true);
                  }}
                  className="bg-slate-900 text-white px-4 py-2 rounded-xl font-bold flex items-center gap-2 shadow-lg"
                >
                  <Plus size={18} /> إضافة منتج
                </button>
              </div>

              <div className="rounded-2xl border border-slate-200 bg-white p-4 md:p-5" data-testid="manage-product-categories">
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                  <div>
                    <h3 className="text-sm md:text-base font-black text-slate-900">إدارة التصنيفات</h3>
                    <p className="text-xs font-bold text-slate-500">إضافة، تعديل، أو حذف التصنيفات من هنا.</p>
                  </div>
                  <div className="flex w-full md:w-auto gap-2">
                    <input type="text" value={categoryDraft} onChange={(event) => setCategoryDraft(event.target.value)} placeholder="تصنيف جديد" className="w-full md:w-56 rounded-xl border border-slate-200 px-3 py-2 text-sm font-bold outline-none focus:border-slate-900" />
                    <button type="button" onClick={handleAddCategory} className="px-4 py-2 rounded-xl bg-slate-900 text-white text-xs font-black">إضافة</button>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  {categoryOptions.map((category) => (
                    <div key={category} className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1">
                      <span className="px-2 text-xs font-black text-slate-700">{category}</span>
                      <button type="button" onClick={() => handleRenameCategory(category)} disabled={category === DEFAULT_CATEGORY_NAME} className="h-7 w-7 rounded-full border border-slate-200 bg-white text-slate-500 inline-flex items-center justify-center disabled:opacity-40" title="تعديل">
                        <Edit3 size={12} />
                      </button>
                      <button type="button" onClick={() => handleDeleteCategory(category)} disabled={category === DEFAULT_CATEGORY_NAME} className="h-7 w-7 rounded-full border border-red-200 bg-white text-red-500 inline-flex items-center justify-center disabled:opacity-40" title="حذف">
                        <Trash2 size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <input
                  type="text"
                  value={productQuery}
                  onChange={(event) => setProductQuery(event.target.value)}
                  placeholder={'بحث عن منتج...'}
                  className="md:col-span-2 w-full bg-white border border-gray-200 rounded-xl px-4 py-3 font-bold outline-none focus:ring-2 focus:ring-slate-900/10"
                />
                <select
                  value={productCategoryFilter}
                  onChange={(event) => setProductCategoryFilter(event.target.value)}
                  className="w-full bg-white border border-gray-200 rounded-xl px-4 py-3 font-bold outline-none focus:ring-2 focus:ring-slate-900/10"
                >
                  {categoryFilterOptions.map((category) => (
                    <option key={category} value={category}>{category}</option>
                  ))}
                </select>
              </div>

              {showProductForm ? (                <form onSubmit={handleSaveProduct} className="bg-slate-50 p-6 md:p-8 rounded-[2rem] border border-gray-200">
                  <h3 className="font-black text-xl mb-6">{editingProduct ? 'تعديل المنتج' : 'نشر منتج جديد'}</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    <div className="md:col-span-2">
                      <label className="block text-sm font-bold mb-2">اسم المنتج</label>
                      <input
                        required
                        type="text"
                        value={productForm.name}
                        onChange={(event) => setProductForm({ ...productForm, name: event.target.value })}
                        className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-bold mb-2">القسم</label>
                      <select
                        required
                        value={productForm.category}
                        onChange={(event) => setProductForm({ ...productForm, category: event.target.value })}
                        className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                      >
                        {categoryOptions.map((category) => (
                          <option key={category}>{category}</option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div className="mb-4">
                    <label className="block text-sm font-bold mb-2">وصف المنتج</label>
                    <textarea
                      rows={4}
                      value={productForm.description}
                      onChange={(event) => setProductForm({ ...productForm, description: event.target.value })}
                      placeholder="اكتب وصفًا واضحًا للزبون..."
                      className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900 resize-y"
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div>
                      <label className="block text-sm font-bold mb-2">السعر الحالي (د.ج)</label>
                      <input
                        required
                        type="number"
                        min="1"
                        value={productForm.price}
                        onChange={(event) => setProductForm({ ...productForm, price: event.target.value })}
                        className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-bold mb-2">السعر قبل الخصم (اختياري)</label>
                      <input
                        type="number"
                        min="0"
                        value={productForm.oldPrice}
                        onChange={(event) => setProductForm({ ...productForm, oldPrice: event.target.value })}
                        className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-bold mb-2">المخزون</label>
                      <input
                        required
                        type="number"
                        min="0"
                        value={productForm.stock}
                        onChange={(event) => setProductForm({ ...productForm, stock: event.target.value })}
                        className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                    <div>
                      <label className="block text-sm font-bold mb-2">صور المنتج</label>
                      <div className="flex gap-2">
                        <input
                          type="url"
                          dir="ltr"
                          value={productImageUrlInput}
                          onChange={(event) => setProductImageUrlInput(event.target.value)}
                          placeholder="https://..."
                          className="flex-1 p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                        />
                        <button
                          type="button"
                          onClick={handleAddProductImageByUrl}
                          className="px-4 py-3 rounded-xl bg-slate-900 text-white text-xs font-black"
                        >
                          إضافة
                        </button>
                      </div>

                      <label className="block text-xs font-bold text-gray-500 mt-3 mb-2">أو ارفع صورة مباشرة عبر ImgBB</label>
                      <input
                        type="file"
                        accept="image/*"
                        onChange={handleUploadProductImage}
                        disabled={imageUploadState.isUploading}
                        className="w-full p-2 rounded-xl border border-dashed border-gray-300 bg-white text-xs font-bold"
                      />
                      <p className="text-[11px] text-slate-500 font-bold mt-1">
                        يتطلب المتغير `VITE_IMGBB_API_KEY` في `.env` (الحد الأقصى 8MB).
                      </p>
                      {imageUploadState.isUploading && (
                        <div className="mt-2">
                          <div className="h-2 w-full rounded-full bg-slate-200 overflow-hidden">
                            <div
                              className="h-full bg-emerald-500 transition-all duration-300"
                              style={{ width: String(imageUploadState.progress) + '%' }}
                            />
                          </div>
                          <p className="mt-1 text-[11px] font-black text-emerald-700">
                            جاري الرفع... {imageUploadState.progress}%
                          </p>
                        </div>
                      )}
                      {imageUploadState.error && (
                        <p className="mt-1 text-[11px] font-black text-red-600">{imageUploadState.error}</p>
                      )}
                      {imageUploadState.success && !imageUploadState.isUploading && (
                        <p className="mt-1 text-[11px] font-black text-emerald-600">{imageUploadState.success}</p>
                      )}

                      <div className="mt-3 space-y-2">
                        {(!Array.isArray(productForm.images) || productForm.images.length === 0) ? (
                          <div className="rounded-xl border border-dashed border-gray-300 p-3 text-xs font-bold text-gray-500">أضف صورة واحدة على الأقل.</div>
                        ) : (
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            {productForm.images.map((imageUrl, imageIndex) => (
                              <div key={imageUrl + '-' + String(imageIndex)} className="rounded-xl border border-gray-200 bg-white p-2 space-y-2">
                                <img src={imageUrl} alt={productForm.name || 'product'} className="h-24 w-full object-cover rounded-lg bg-slate-100" loading="lazy" decoding="async" />
                                <div className="flex flex-wrap gap-1">
                                  <button type="button" onClick={() => handleSetPrimaryProductImage(imageIndex)} className="px-2 py-1 rounded-md text-[10px] font-black border border-slate-200 bg-slate-50">رئيسية</button>
                                  <button type="button" onClick={() => handleMoveProductImage(imageIndex, -1)} disabled={imageIndex === 0} className="px-2 py-1 rounded-md text-[10px] font-black border border-slate-200 bg-slate-50 disabled:opacity-40">لأمام</button>
                                  <button type="button" onClick={() => handleMoveProductImage(imageIndex, 1)} disabled={imageIndex === productForm.images.length - 1} className="px-2 py-1 rounded-md text-[10px] font-black border border-slate-200 bg-slate-50 disabled:opacity-40">للخلف</button>
                                  <button type="button" onClick={() => handleRemoveProductImage(imageIndex)} className="px-2 py-1 rounded-md text-[10px] font-black border border-red-200 text-red-600 bg-red-50">حذف</button>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="rounded-2xl border border-gray-200 bg-white p-4 space-y-4">
                      <p className="font-black text-sm">السمات الديناميكية</p>

                      <div className="flex items-center justify-between">
                        <label className="text-sm font-bold inline-flex items-center gap-1"><Ruler size={14} /> تفعيل المقاسات</label>
                        <input
                          type="checkbox"
                          checked={productForm.variants.enableSizes}
                          onChange={(event) => {
                            const enabled = event.target.checked;
                            setProductForm({
                              ...productForm,
                              variants: {
                                ...productForm.variants,
                                enableSizes: enabled,
                                sizes: enabled ? productForm.variants.sizes : [],
                              },
                            });
                          }}
                          className="w-5 h-5 accent-emerald-500"
                        />
                      </div>

                      {productForm.variants.enableSizes && (
                        <div className="space-y-2">
                          <select
                            value={productForm.variants.sizeType}
                            onChange={(event) =>
                              setProductForm({
                                ...productForm,
                                variants: {
                                  ...productForm.variants,
                                  sizeType: event.target.value,
                                  sizes: [],
                                },
                              })
                            }
                            className="w-full p-2 rounded-lg border border-gray-300 text-sm font-bold"
                          >
                            <option value="clothing">مقاسات ملابس (S-XXL)</option>
                            <option value="shoes">مقاسات أحذية (37-45)</option>
                          </select>

                          <div className="flex flex-wrap gap-2">
                            {sizeOptions.map((size) => {
                              const isActive = productForm.variants.sizes.includes(size);
                              return (
                                <button
                                  type="button"
                                  key={size}
                                  onClick={() => {
                                    const nextSizes = isActive
                                      ? productForm.variants.sizes.filter((entry) => entry !== size)
                                      : [...productForm.variants.sizes, size];
                                    setProductForm({
                                      ...productForm,
                                      variants: { ...productForm.variants, sizes: nextSizes },
                                    });
                                  }}
                                  className={`px-2 py-1 rounded-md border text-xs font-black ${isActive ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-300'}`}
                                >
                                  {size}
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      <div className="flex items-center justify-between">
                        <label className="text-sm font-bold inline-flex items-center gap-1"><Palette size={14} /> تفعيل الألوان</label>
                        <input
                          type="checkbox"
                          checked={productForm.variants.enableColors}
                          onChange={(event) => {
                            const enabled = event.target.checked;
                            setProductForm({
                              ...productForm,
                              variants: {
                                ...productForm.variants,
                                enableColors: enabled,
                                colors: enabled ? productForm.variants.colors : [],
                              },
                            });
                          }}
                          className="w-5 h-5 accent-emerald-500"
                        />
                      </div>

                      {productForm.variants.enableColors && (
                        <div className="flex flex-wrap gap-2">
                          {COLOR_PRESETS.map((colorEntry) => {
                            const isActive = productForm.variants.colors.includes(colorEntry.name);
                            return (
                              <button
                                type="button"
                                key={colorEntry.name}
                                onClick={() => {
                                  const nextColors = isActive
                                    ? productForm.variants.colors.filter((entry) => entry !== colorEntry.name)
                                    : [...productForm.variants.colors, colorEntry.name];
                                  setProductForm({
                                    ...productForm,
                                    variants: { ...productForm.variants, colors: nextColors },
                                  });
                                }}
                                className={`px-2 py-1 rounded-md border text-xs font-black inline-flex items-center gap-1 ${isActive ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-300'}`}
                              >
                                <span className="w-3 h-3 rounded-full border border-white/50" style={{ backgroundColor: colorEntry.hex }} />
                                {colorEntry.name}
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex gap-3">
                    <button type="submit" className="flex-1 bg-emerald-500 text-white font-black py-3 rounded-xl shadow-md">
                      {editingProduct ? 'حفظ التعديلات' : 'نشر المنتج'}
                    </button>
                    <button
                      type="button"
                      onClick={() => { resetProductForm(); setShowProductForm(false); }}
                      className="px-6 bg-white border border-gray-300 text-gray-600 font-bold rounded-xl"
                    >
                      إلغاء
                    </button>
                  </div>
                </form>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-4">
                  {filteredProducts.map((product) => {
                    const stock = clampStock(product.stock);
                    return (
                      <div key={product.id} className="bg-white border border-gray-100 rounded-2xl overflow-hidden shadow-sm group">
                        <img src={product.image || (Array.isArray(product.images) ? product.images[0] : "")} loading="lazy" decoding="async" className="w-full h-40 object-cover bg-gray-50" alt={product.name} />
                        <div className="p-4">
                          <p className="font-bold text-sm truncate mb-1">{product.name}</p>
                          <p className="text-[11px] font-black text-slate-500 mb-1">{product.category}</p>
                          {product.description && <p className="text-[11px] font-bold text-slate-500 line-clamp-2 mb-2">{product.description}</p>}
                          <p className="font-black text-emerald-600 mb-1">{product.price} د.ج</p>
                          <p
                            className={`text-xs font-black mb-4 ${
                              stock === 0 ? 'text-red-600' : stock <= 3 ? 'text-orange-600' : 'text-gray-500'
                            }`}
                          >
                            المخزون: {stock}
                          </p>
                          <div className="mb-3 flex flex-wrap gap-1">
                            {normalizeProductVariants(product.variants).enableSizes && (
                              <span className="text-[10px] px-2 py-1 rounded-full bg-blue-50 text-blue-700 font-black">مقاسات</span>
                            )}
                            {normalizeProductVariants(product.variants).enableColors && (
                              <span className="text-[10px] px-2 py-1 rounded-full bg-purple-50 text-purple-700 font-black">ألوان</span>
                            )}
                            {isProductOnSale(product) && (
                              <span className="text-[10px] px-2 py-1 rounded-full bg-rose-50 text-rose-700 font-black">خصم {getDiscountPercent(product)}%</span>
                            )}
                          </div>
                          <div className="flex gap-2">
                            <button
                              onClick={() => {
                                setProductForm({
                                  ...product,
                                  name: String(product.name || ''),
                                  description: String(product.description || ''),
                                  category: categoryOptions.includes(product.category) ? product.category : (categoryOptions[0] || DEFAULT_CATEGORY_NAME),
                                  image: normalizeFormImages(product).image,
                                  images: normalizeFormImages(product).images,
                                  stock: clampStock(product.stock),
                                  oldPrice: Number(product.oldPrice) > 0 ? product.oldPrice : '',
                                  variants: normalizeProductVariants(product.variants),
                                });
                                setEditingProduct(product);
                                setImageUploadState({ isUploading: false, progress: 0, error: '', success: '' });
                                setProductImageUrlInput('');
                                setShowProductForm(true);
                              }}
                              className="flex-1 bg-blue-50 text-blue-600 py-2 rounded-lg text-xs font-bold flex items-center justify-center gap-1"
                            >
                              <Edit3 size={14} /> تعديل
                            </button>
                            <button
                              onClick={() => handleDeleteProduct(product.id)}
                              className="bg-red-50 text-red-600 p-2 rounded-lg"
                            >
                              <Trash2 size={16} />
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'telegram' && (
            <div className="space-y-6 animate-in fade-in max-w-4xl">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <h2 className="text-2xl font-black text-slate-900 inline-flex items-center gap-2"><MessageCircle size={22} /> ربط تيليجرام</h2>
                <span
                  className={
                    'px-3 py-1.5 rounded-full text-xs font-black border ' +
                    (telegramSettings.connectionStatus === 'connected'
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : telegramSettings.connectionStatus === 'not_verified'
                      ? 'bg-amber-50 text-amber-700 border-amber-200'
                      : 'bg-slate-100 text-slate-600 border-slate-200')
                  }
                >
                  {telegramSettings.connectionStatus === 'connected' ? 'متصل' : telegramSettings.connectionStatus === 'not_verified' ? 'غير مؤكد' : 'غير متصل'}
                </span>
              </div>

              <div className="bg-white border border-gray-200 p-6 md:p-8 rounded-[2rem] space-y-6">
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => loadTelegramSettings(false)}
                    disabled={isTelegramLoading}
                    className="px-3 py-2 rounded-xl text-xs font-black border border-slate-300 text-slate-600 hover:bg-slate-50 disabled:opacity-60"
                  >
                    {isTelegramLoading ? 'جارٍ التحميل...' : 'تحديث'}
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2" dir="ltr">Bot Token</label>
                    <input
                      type="password"
                      dir="ltr"
                      value={telegramSettings.botToken}
                      onChange={(event) => setTelegramSettings((previous) => ({ ...previous, botToken: event.target.value }))}
                      placeholder={telegramSettings.hasToken ? 'أدخل Token جديد للتحديث (اختياري)' : 'أدخل Bot Token'}
                      className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                    />
                    {telegramSettings.botTokenMasked && (
                      <p className="mt-2 text-xs font-black text-slate-500" dir="ltr">المحفوظ: {telegramSettings.botTokenMasked}</p>
                    )}
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2" dir="ltr">Chat ID</label>
                    <input
                      type="text"
                      dir="ltr"
                      value={telegramSettings.chatId}
                      onChange={(event) => setTelegramSettings((previous) => ({ ...previous, chatId: event.target.value }))}
                      placeholder="مثال: -1001234567890"
                      className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                    />
                    {telegramSettings.chatIdMasked && (
                      <p className="mt-2 text-xs font-black text-slate-500" dir="ltr">Masked: {telegramSettings.chatIdMasked}</p>
                    )}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setTelegramSettings((previous) => ({ ...previous, enabled: !previous.enabled }))}
                    className={
                      'px-3 py-2 rounded-xl text-xs font-black border transition ' +
                      (telegramSettings.enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-50 text-slate-600 border-slate-200')
                    }
                  >
                    {telegramSettings.enabled ? 'الإشعارات مفعّلة' : 'الإشعارات معطلة'}
                  </button>
                </div>

                <div className="rounded-2xl border border-slate-200 p-4 space-y-3">
                  <p className="text-sm font-black text-slate-900">أنواع الإشعارات</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-bold text-slate-700">
                    <label className="flex items-center justify-between rounded-xl border border-slate-200 px-3 py-2">
                      <span>طلب جديد</span>
                      <input type="checkbox" checked={telegramSettings.notifications.newOrder} onChange={(event) => setTelegramSettings((previous) => ({ ...previous, notifications: { ...previous.notifications, newOrder: event.target.checked } }))} className="w-4 h-4 accent-emerald-500" />
                    </label>
                    <label className="flex items-center justify-between rounded-xl border border-slate-200 px-3 py-2">
                      <span>تغيير حالة الطلب</span>
                      <input type="checkbox" checked={telegramSettings.notifications.orderStatus} onChange={(event) => setTelegramSettings((previous) => ({ ...previous, notifications: { ...previous.notifications, orderStatus: event.target.checked } }))} className="w-4 h-4 accent-emerald-500" />
                    </label>
                    <label className="flex items-center justify-between rounded-xl border border-slate-200 px-3 py-2">
                      <span>عمليات إدارية</span>
                      <input type="checkbox" checked={telegramSettings.notifications.adminActions} onChange={(event) => setTelegramSettings((previous) => ({ ...previous, notifications: { ...previous.notifications, adminActions: event.target.checked } }))} className="w-4 h-4 accent-emerald-500" />
                    </label>
                    <label className="flex items-center justify-between rounded-xl border border-slate-200 px-3 py-2">
                      <span>أخطاء النظام</span>
                      <input type="checkbox" checked={telegramSettings.notifications.systemErrors} onChange={(event) => setTelegramSettings((previous) => ({ ...previous, notifications: { ...previous.notifications, systemErrors: event.target.checked } }))} className="w-4 h-4 accent-emerald-500" />
                    </label>
                  </div>
                </div>

                {telegramSettings.lastTestAt && (
                  <p className="text-xs font-black text-slate-500">آخر اختبار: {new Date(telegramSettings.lastTestAt).toLocaleString('ar-DZ')}</p>
                )}
                {telegramSettings.lastError && (
                  <p className="text-xs font-black text-red-600">{telegramSettings.lastError}</p>
                )}

                <div className="flex flex-wrap gap-3 justify-end">
                  <button
                    type="button"
                    onClick={handleTestTelegramSettings}
                    disabled={isTelegramTesting || isTelegramSaving || isTelegramLoading}
                    className="bg-blue-600 text-white px-6 py-3 rounded-xl font-black shadow-lg disabled:opacity-60"
                  >
                    {isTelegramTesting ? 'جارٍ الاختبار...' : 'اختبار الاتصال'}
                  </button>
                  <button
                    type="button"
                    onClick={handleSaveTelegramSettings}
                    disabled={isTelegramSaving || isTelegramLoading}
                    className="bg-slate-900 text-white px-6 py-3 rounded-xl font-black shadow-lg disabled:opacity-60"
                  >
                    {isTelegramSaving ? 'جارٍ الحفظ...' : 'حفظ الإعدادات'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <AdminSecurityCenter
              isDarkMode={isDarkMode}
              showToast={showToast}
              adminUser={adminUser}
              pageTransition={PAGE_TRANSITION}
            />
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6 animate-in fade-in max-w-2xl">
              <h2 className="text-2xl font-black text-slate-900 mb-6">{'إعدادات المتجر الأساسية'}</h2>

              <div className="bg-white border border-gray-200 p-6 md:p-8 rounded-[2rem] space-y-8">
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-2">{'اسم المتجر'}</label>
                  <input
                    type="text"
                    value={siteConfig.name}
                    onChange={(event) => setSiteConfig({ ...siteConfig, name: event.target.value })}
                    className="w-full p-4 rounded-xl border border-gray-300 font-black text-lg outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-900/10 transition-all"
                  />
                </div>
                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-2">{'شعار المتجر'}</label>
                  <div className="flex flex-col sm:flex-row items-start gap-3 rounded-2xl border border-gray-200 bg-slate-50 p-3">
                    <div className="h-16 w-16 rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-sm shrink-0">
                      {siteConfig.logoUrl ? (
                        <img
                          src={siteConfig.logoUrl}
                          alt={siteConfig.name || 'store-logo'}
                          className="h-full w-full object-cover"
                          loading="lazy"
                          decoding="async"
                        />
                      ) : (
                        <span className="h-full w-full inline-flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-cyan-700 text-white font-black text-xl">
                          {String(siteConfig.name || 'S').trim().charAt(0) || 'S'}
                        </span>
                      )}
                    </div>

                    <div className="flex-1 w-full space-y-2">
                      <input
                        type="url"
                        dir="ltr"
                        value={siteConfig.logoUrl || ''}
                        onChange={(event) => setSiteConfig({ ...siteConfig, logoUrl: event.target.value })}
                        placeholder="https://..."
                        className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-900/10 transition-all"
                      />

                      <div className="flex flex-wrap gap-2">
                        <label className="px-3 py-2 rounded-xl border border-dashed border-gray-300 bg-white text-xs font-black text-slate-600 cursor-pointer">
                          {'رفع شعار'}
                          <input type="file" accept="image/*" onChange={handleUploadStoreLogo} className="hidden" disabled={logoUploadState.isUploading} />
                        </label>

                        <button
                          type="button"
                          onClick={() => {
                            setSiteConfig({ ...siteConfig, logoUrl: '' });
                            setLogoUploadState({ isUploading: false, progress: 0, error: '', success: '' });
                          }}
                          className="px-3 py-2 rounded-xl border border-slate-200 bg-white text-xs font-black text-slate-600 hover:bg-slate-100"
                        >
                          {'إزالة'}
                        </button>
                      </div>

                      {logoUploadState.isUploading && <p className="text-[11px] font-black text-emerald-700">{'جارٍ رفع الشعار...'} {logoUploadState.progress}%</p>}
                      {logoUploadState.error && <p className="text-[11px] font-black text-red-600">{logoUploadState.error}</p>}
                      {logoUploadState.success && !logoUploadState.isUploading && <p className="text-[11px] font-black text-emerald-600">{logoUploadState.success}</p>}
                    </div>
                  </div>
                </div>


                <div>
                  <label className="block text-sm font-bold text-gray-700 mb-2">{'رقم واتساب المتجر'}</label>
                  <input
                    type="tel"
                    dir="ltr"
                    value={siteConfig.whatsappNumber || ''}
                    onChange={(event) => setSiteConfig({ ...siteConfig, whatsappNumber: event.target.value })}
                    placeholder="213555000000"
                    className="w-full p-4 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-900/10 transition-all"
                  />
                  <p className="text-xs font-bold text-gray-500 mt-2">{'سيظهر في الزر العائم للتواصل عبر واتساب.'}</p>
                </div>


                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">{'\u0631\u0627\u0628\u0637 \u0635\u0641\u062d\u0629 \u0641\u064a\u0633\u0628\u0648\u0643'}</label>
                    <input
                      type="url"
                      dir="ltr"
                      value={siteConfig.facebookUrl || ''}
                      onChange={(event) => setSiteConfig({ ...siteConfig, facebookUrl: event.target.value })}
                      placeholder="https://facebook.com/your-page"
                      className="w-full p-4 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-900/10 transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">{'\u0631\u0627\u0628\u0637 \u0625\u0646\u0633\u062a\u063a\u0631\u0627\u0645'}</label>
                    <input
                      type="url"
                      dir="ltr"
                      value={siteConfig.instagramUrl || ''}
                      onChange={(event) => setSiteConfig({ ...siteConfig, instagramUrl: event.target.value })}
                      placeholder="https://instagram.com/your-store"
                      className="w-full p-4 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-900/10 transition-all"
                    />
                  </div>
                </div>

                <div className="pt-6 border-t border-gray-100 space-y-4">
                  <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                    <div>
                      <h3 className="text-base font-black text-slate-900">أسعار التوصيل حسب الولاية</h3>
                      <p className="text-xs font-bold text-gray-500 mt-1">الأسعار تُطبّق تلقائيًا في صفحة إتمام الطلب حسب الولاية المختارة.</p>
                    </div>
                    <div className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-black text-slate-600">
                      <span>ولايات بسعر مخصص:</span>
                      <span className="text-emerald-600">{configuredWilayaShippingCount}</span>
                      <span>/</span>
                      <span>{wilayaShippingOptions.length || 58}</span>
                    </div>
                  </div>

                  <div className="flex flex-col gap-3 md:flex-row md:items-center">
                    <div className="relative flex-1">
                      <Search size={16} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-slate-400" />
                      <input
                        type="text"
                        value={shippingWilayaSearch}
                        onChange={(event) => setShippingWilayaSearch(event.target.value)}
                        placeholder="ابحث باسم الولاية أو رقمها..."
                        className="w-full rounded-xl border border-gray-300 bg-white py-3 pr-10 pl-3 text-sm font-bold text-slate-700 outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-900/10"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={handleResetShippingFees}
                      disabled={configuredWilayaShippingCount === 0}
                      className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-xs font-black text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      إعادة ضبط كل الأسعار
                    </button>
                  </div>

                  {isWilayaShippingLoading && (
                    <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 px-4 py-5 text-center text-sm font-black text-slate-500">
                      جارٍ تحميل قائمة الولايات...
                    </div>
                  )}

                  {wilayaShippingError && !isWilayaShippingLoading && (
                    <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-4 text-sm font-black text-red-600">
                      {wilayaShippingError}
                    </div>
                  )}

                  {!isWilayaShippingLoading && !wilayaShippingError && (
                    <div className="max-h-[22rem] overflow-y-auto rounded-2xl border border-gray-200 bg-slate-50 p-2">
                      <div className="space-y-2">
                        {filteredWilayaShippingOptions.length === 0 ? (
                          <div className="rounded-xl border border-dashed border-slate-200 bg-white px-4 py-5 text-center text-xs font-black text-slate-500">
                            لا توجد ولايات مطابقة للبحث.
                          </div>
                        ) : (
                          filteredWilayaShippingOptions.map((wilaya) => {
                            const wilayaCode = String(wilaya.wilaya_code || "").padStart(2, "0");
                            const shippingValue = Object.prototype.hasOwnProperty.call(shippingFeesByWilaya, wilayaCode)
                              ? String(shippingFeesByWilaya[wilayaCode])
                              : "";

                            return (
                              <div key={wilayaCode} className="grid gap-2 rounded-xl border border-slate-200 bg-white p-3 md:grid-cols-[minmax(0,1fr)_11rem] md:items-center">
                                <div>
                                  <p className="text-sm font-black text-slate-900">{wilaya.wilaya_name}</p>
                                  <p className="text-[11px] font-bold text-slate-500">الرمز: {wilayaCode}</p>
                                </div>
                                <div className="relative">
                                  <input
                                    type="number"
                                    min="0"
                                    step="10"
                                    value={shippingValue}
                                    onChange={(event) => handleShippingFeeChange(wilayaCode, event.target.value)}
                                    placeholder="0"
                                    className="w-full rounded-xl border border-gray-300 bg-white py-2.5 pr-3 pl-12 text-sm font-black text-slate-800 outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
                                  />
                                  <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-xs font-black text-slate-500">د.ج</span>
                                </div>
                              </div>
                            );
                          })
                        )}
                      </div>
                    </div>
                  )}

                  <p className="text-xs font-bold text-gray-500">
                    إذا تُرك السعر فارغًا، يتم اعتماد سعر توصيل افتراضي 0 د.ج لتلك الولاية.
                  </p>
                </div>

                <div className="pt-6 border-t border-gray-100">
                  <div className="flex items-center justify-between mb-2">
                    <label className="block text-sm font-bold text-gray-700">{'حالة المتجر (إغلاق / فتح)'}</label>
                    <span className={
                      'px-3 py-1 rounded-full text-xs font-bold ' +
                      (siteConfig.isOnline ? 'bg-emerald-100 text-emerald-700' : 'bg-orange-100 text-orange-700')
                    }>
                      {siteConfig.isOnline ? 'نشط الآن' : 'مغلق للصيانة'}
                    </span>
                  </div>

                  <button
                    onClick={() => {
                      setSiteConfig({ ...siteConfig, isOnline: !siteConfig.isOnline });
                      showToast(siteConfig.isOnline ? 'تم إغلاق المتجر للزبائن' : 'تم فتح المتجر للزبائن');
                    }}
                    className={
                      'w-full py-4 rounded-xl font-black flex items-center justify-center gap-2 transition-all ' +
                      (siteConfig.isOnline
                        ? 'bg-orange-50 text-orange-600 border border-orange-200 hover:bg-orange-100'
                        : 'bg-emerald-500 text-white shadow-lg hover:bg-emerald-600')
                    }
                  >
                    <Power size={20} /> {siteConfig.isOnline ? 'تفعيل وضع الصيانة' : 'فتح المتجر'}
                  </button>
                </div>

                <div className="pt-6 border-t border-gray-100">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-black text-slate-900">{'إظهار حقل الكوبون للعميل'}</p>
                      <p className="text-xs font-bold text-gray-500 mt-1">{'يمكنك إخفاء حقل الكوبون مؤقتاً مع الاحتفاظ بالمنطق الداخلي.'}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setSiteConfig({ ...siteConfig, showCouponInput: !siteConfig.showCouponInput })}
                      className={
                        'px-3 py-2 rounded-xl text-xs font-black border transition ' +
                        (siteConfig.showCouponInput
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-slate-50 text-slate-600 border-slate-200')
                      }
                    >
                      {siteConfig.showCouponInput ? 'ظاهر حالياً' : 'مخفي حالياً'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'marketing' && (
            <div className="space-y-6 animate-in fade-in max-w-3xl">
              <h2 className="text-2xl font-black text-slate-900 mb-6">التسويق والإعلانات</h2>

              <div className="bg-gradient-to-br from-emerald-500 to-teal-600 p-8 rounded-[2rem] text-white shadow-xl">
                <div className="flex items-center gap-3 mb-6">
                  <Megaphone size={32} className="text-emerald-100" />
                  <h3 className="text-xl font-black">شريط الإعلانات العلوي</h3>
                </div>

                <input
                  type="text"
                  value={siteConfig.announcement}
                  onChange={(event) => setSiteConfig({ ...siteConfig, announcement: event.target.value })}
                  placeholder="مثال: توصيل مجاني هذا الأسبوع"
                  className="w-full p-4 rounded-xl bg-white/20 border border-white/30 text-white placeholder-emerald-200 font-bold outline-none focus:bg-white/30 transition-all mb-4"
                />

                <div className="flex gap-3">
                  <button onClick={() => showToast('تم تحديث شريط الإعلانات')} className="bg-slate-900 text-white px-6 py-3 rounded-xl font-black shadow-lg">
                    حفظ الإعلان
                  </button>
                  <button
                    onClick={() => {
                      setSiteConfig({ ...siteConfig, announcement: '' });
                      showToast('تم إخفاء الإعلان');
                    }}
                    className="bg-white/10 hover:bg-white/20 text-white px-6 py-3 rounded-xl font-bold transition-all border border-white/20"
                  >
                    إخفاء الإعلان
                  </button>
                </div>
              </div>
              <div className="bg-white border border-gray-200 p-6 md:p-8 rounded-[2rem] space-y-6" data-testid="customer-notices-manager">
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                  <h3 className="text-xl font-black text-slate-900">إشعارات الزبائن</h3>
                  <button type="button" onClick={resetNoticeForm} className="px-3 py-2 rounded-xl border border-slate-200 text-xs font-black text-slate-600 hover:bg-slate-50">إشعار جديد</button>
                </div>

                <form onSubmit={handleSaveNotice} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">العنوان</label>
                    <input type="text" value={noticeForm.title} onChange={(event) => setNoticeForm({ ...noticeForm, title: event.target.value })} className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900" />
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">مستوى الأهمية</label>
                    <select value={noticeForm.level} onChange={(event) => setNoticeForm({ ...noticeForm, level: event.target.value })} className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900">
                      {NOTICE_LEVEL_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label className="block text-sm font-bold text-gray-700 mb-2">نص الإشعار</label>
                    <textarea rows={3} value={noticeForm.message} onChange={(event) => setNoticeForm({ ...noticeForm, message: event.target.value })} className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900" />
                  </div>
                  <div className="md:col-span-2">
                    <label className="block text-sm font-bold text-gray-700 mb-2">صورة (اختياري)</label>
                    <div className="flex gap-2">
                      <input type="url" dir="ltr" value={noticeForm.image} onChange={(event) => setNoticeForm({ ...noticeForm, image: event.target.value })} placeholder="https://..." className="flex-1 p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900" />
                      <label className="px-3 py-3 rounded-xl border border-dashed border-gray-300 bg-gray-50 text-xs font-black text-slate-600 cursor-pointer">
                        رفع
                        <input type="file" accept="image/*" onChange={handleUploadNoticeImage} className="hidden" />
                      </label>
                    </div>
                    {noticeImageUploadState.isUploading && <p className="mt-1 text-[11px] font-black text-emerald-700">جاري رفع الصورة... {noticeImageUploadState.progress}%</p>}
                    {noticeImageUploadState.error && <p className="mt-1 text-[11px] font-black text-red-600">{noticeImageUploadState.error}</p>}
                    {noticeImageUploadState.success && !noticeImageUploadState.isUploading && <p className="mt-1 text-[11px] font-black text-emerald-600">{noticeImageUploadState.success}</p>}
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">الأولوية</label>
                    <input type="number" value={noticeForm.priority} onChange={(event) => setNoticeForm({ ...noticeForm, priority: Number(event.target.value) || 0 })} className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900" />
                  </div>
                  <div className="flex items-end">
                    <label className="inline-flex items-center gap-2 text-sm font-bold text-slate-700">
                      <input type="checkbox" checked={noticeForm.enabled} onChange={(event) => setNoticeForm({ ...noticeForm, enabled: event.target.checked })} className="w-4 h-4 accent-emerald-500" />
                      مفعل
                    </label>
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">من تاريخ (اختياري)</label>
                    <input type="datetime-local" value={noticeForm.startAt} onChange={(event) => setNoticeForm({ ...noticeForm, startAt: event.target.value })} className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900" />
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">إلى تاريخ (اختياري)</label>
                    <input type="datetime-local" value={noticeForm.endAt} onChange={(event) => setNoticeForm({ ...noticeForm, endAt: event.target.value })} className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900" />
                  </div>
                  <div className="md:col-span-2 flex gap-3">
                    <button type="submit" className="bg-slate-900 text-white px-6 py-3 rounded-xl font-black shadow-lg">{editingNoticeId ? 'حفظ التعديل' : 'إنشاء إشعار'}</button>
                    {editingNoticeId && <button type="button" onClick={resetNoticeForm} className="bg-gray-100 text-gray-700 px-6 py-3 rounded-xl font-bold">إلغاء التعديل</button>}
                  </div>
                </form>

                <div className="space-y-3">
                  {customerNotices.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-gray-200 p-4 text-center text-sm font-bold text-gray-400">لا توجد إشعارات حالياً.</div>
                  ) : (
                    customerNotices.map((notice) => (
                      <div key={notice.id} className="rounded-xl border border-gray-200 p-4 space-y-2">
                        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                          <div>
                            <p className="font-black text-slate-900">{notice.title || 'بدون عنوان'}</p>
                            <p className="text-xs font-bold text-slate-500">{(NOTICE_LEVEL_OPTIONS.find((entry) => entry.value === notice.level)?.label || notice.level)} - P{Number(notice.priority) || 0}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <button type="button" onClick={() => handleToggleNoticeEnabled(notice.id)} className={'px-3 py-1.5 rounded-lg text-xs font-black border ' + (notice.enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-600 border-slate-200')}>{notice.enabled ? 'مفعل' : 'معطل'}</button>
                            <button type="button" onClick={() => handleEditNotice(notice)} className="px-3 py-1.5 rounded-lg text-xs font-black border border-blue-200 bg-blue-50 text-blue-700">تعديل</button>
                            <button type="button" onClick={() => handleDeleteNotice(notice.id)} className="px-3 py-1.5 rounded-lg text-xs font-black border border-red-200 bg-red-50 text-red-700">حذف</button>
                          </div>
                        </div>
                        {notice.message && <p className="text-sm font-bold text-slate-700 whitespace-pre-line">{notice.message}</p>}
                        {notice.image && <img src={notice.image} alt={notice.title || 'notice'} className="h-28 w-full object-cover rounded-lg border border-slate-100" loading="lazy" decoding="async" />}
                      </div>
                    ))
                  )}
                </div>
              </div>


                            <div className="bg-white border border-gray-200 p-6 md:p-8 rounded-[2rem] space-y-6">
                <h3 className="text-xl font-black text-slate-900">كوبونات الخصم المتقدمة</h3>

                <form onSubmit={handleCreateCoupon} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">رمز الكوبون</label>
                    <input
                      type="text"
                      dir="ltr"
                      value={couponForm.code}
                      onChange={(event) => setCouponForm({ ...couponForm, code: event.target.value.toUpperCase() })}
                      placeholder="WELCOME10"
                      className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">نسبة الخصم %</label>
                    <input
                      type="number"
                      min="1"
                      max="90"
                      value={couponForm.discount}
                      onChange={(event) => setCouponForm({ ...couponForm, discount: clampDiscount(event.target.value) })}
                      className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">عدد الاستخدامات المسموحة</label>
                    <input
                      type="number"
                      min="1"
                      value={couponForm.maxUses}
                      onChange={(event) => setCouponForm({ ...couponForm, maxUses: clampUses(event.target.value) })}
                      className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-bold text-gray-700 mb-2">تاريخ الانتهاء (اختياري)</label>
                    <input
                      type="date"
                      value={couponForm.expiresAt}
                      onChange={(event) => setCouponForm({ ...couponForm, expiresAt: event.target.value })}
                      className="w-full p-3 rounded-xl border border-gray-300 font-bold outline-none focus:border-slate-900"
                    />
                  </div>

                  <div className="md:col-span-2 flex gap-3">
                    <button type="submit" className="bg-slate-900 text-white px-6 py-3 rounded-xl font-black shadow-lg">
                      إنشاء كوبون
                    </button>
                    <button
                      type="button"
                      onClick={() => setCouponForm({ code: '', discount: 10, maxUses: 100, expiresAt: '' })}
                      className="bg-gray-100 text-gray-700 px-6 py-3 rounded-xl font-bold"
                    >
                      تفريغ الحقول
                    </button>
                  </div>
                </form>

                {adminCoupons.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-gray-200 p-4 text-center text-sm font-bold text-gray-400">
                    لا توجد كوبونات مضافة حتى الآن.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {adminCoupons.map((coupon) => {
                      const expired = isCouponExpired(coupon);
                      const exhausted = isCouponExhausted(coupon);
                      return (
                        <div key={coupon.id} className="rounded-xl border border-gray-200 p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
                          <div className="space-y-1">
                            <p className="font-black text-slate-900" dir="ltr">{coupon.code}</p>
                            <p className="text-xs font-bold text-gray-500">خصم {coupon.discount}% • الاستخدام {coupon.usedCount}/{coupon.maxUses}</p>
                            {coupon.expiresAt && (
                              <p className="text-xs font-bold text-gray-500">ينتهي: {new Date(coupon.expiresAt).toLocaleDateString('ar-DZ')}</p>
                            )}
                            <p className={`text-xs font-black ${expired || exhausted ? 'text-red-600' : 'text-emerald-600'}`}>
                              {expired ? 'منتهي الصلاحية' : exhausted ? 'نفد الاستخدام' : 'فعّال'}
                            </p>
                          </div>
                          <button
                            onClick={() => handleDeleteCoupon(coupon.id)}
                            className="bg-red-50 text-red-600 px-4 py-2 rounded-lg font-bold"
                          >
                            حذف
                          </button>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </Motion.div>
  );
};
export default AdminCMS;






