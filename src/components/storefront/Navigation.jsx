import React from 'react';
import { AnimatePresence, motion as Motion } from 'framer-motion';
import {
  BadgePercent,
  Compass,
  Heart,
  Home,
  Facebook,
  Instagram,
  LogOut,
  MessageCircle,
  Search,
  ShoppingBag,
  ShoppingCart,
  Sparkles,
  User,
} from 'lucide-react';

const TEXT = {
  whatsappMessage: '\u0645\u0631\u062d\u0628\u0627\u064b\u060c \u0623\u0631\u064a\u062f \u0627\u0644\u0627\u0633\u062a\u0641\u0633\u0627\u0631 \u0639\u0646 \u0645\u0646\u062a\u062c\u0627\u062a \u0627\u0644\u0645\u062a\u062c\u0631.',
  whatsappLabel: '\u062a\u0648\u0627\u0635\u0644 \u0648\u0627\u062a\u0633\u0627\u0628',
  whatsappTitle: '\u062a\u0648\u0627\u0635\u0644 \u0639\u0628\u0631 \u0648\u0627\u062a\u0633\u0627\u0628',
  whatsapp: '\u0648\u0627\u062a\u0633\u0627\u0628',
  facebook: '\u0641\u064a\u0633\u0628\u0648\u0643',
  instagram: '\u0625\u0646\u0633\u062a\u063a\u0631\u0627\u0645',
  subtitlePrefix: '\u0627\u0644\u0645\u062a\u062c\u0631 \u0627\u0644\u0631\u0633\u0645\u064a \u0644\u0640 ',
  searchPlaceholder: '\u0627\u0628\u062d\u062b \u0639\u0646 \u0627\u0644\u0645\u0646\u062a\u062c\u0627\u062a...',
  home: '\u0627\u0644\u0631\u0626\u064a\u0633\u064a\u0629',
  offers: '\u0627\u0644\u0639\u0631\u0648\u0636',
  track: '\u062a\u062a\u0628\u0639',
  favorites: '\u0627\u0644\u0645\u0641\u0636\u0644\u0629',
  admin: '\u0627\u0644\u0625\u062f\u0627\u0631\u0629',
  login: '\u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644',
  cart: '\u0627\u0644\u0633\u0644\u0629',
  account: '\u062d\u0633\u0627\u0628\u064a',
  footerDesc: '\u062a\u062c\u0631\u0628\u0629 \u062a\u0633\u0648\u0642 \u062d\u062f\u064a\u062b\u0629\u060c \u0633\u0631\u064a\u0639\u0629\u060c \u0648\u0645\u0646\u0627\u0633\u0628\u0629 \u0644\u0644\u0647\u0627\u062a\u0641.',
  note: '\u0645\u0644\u0627\u062d\u0638\u0629',
  footerNote: '\u0627\u0644\u0623\u0633\u0639\u0627\u0631 \u0648\u0627\u0644\u0645\u062e\u0632\u0648\u0646 \u064a\u062a\u0645 \u062a\u062d\u062f\u064a\u062b\u0647\u0645\u0627 \u0628\u0627\u0633\u062a\u0645\u0631\u0627\u0631 \u0645\u0646 \u0644\u0648\u062d\u0629 \u0627\u0644\u0625\u062f\u0627\u0631\u0629.',
  trackOrder: '\u062a\u062a\u0628\u0639 \u0627\u0644\u0637\u0644\u0628',
};

const AnnouncementBar = ({ text }) => {
  if (!text) return null;
  return (
    <div className="bg-gradient-to-l from-cyan-500 via-teal-500 to-emerald-500 text-white text-xs md:text-sm font-black py-2.5 px-4 text-center shadow-lg shadow-cyan-700/20">
      {text}
    </div>
  );
};

const normalizeWhatsappNumber = (value) => String(value || '').replace(/[^\d]/g, '');

const StoreLogo = ({ siteName, siteLogo, className = 'h-12 w-12 rounded-2xl' }) => {
  const [isBroken, setIsBroken] = React.useState(false);
  const hasLogo = Boolean(siteLogo) && !isBroken;
  const letter = String(siteName || 'S').trim().charAt(0) || 'S';

  return (
    <div className={`${className} overflow-hidden border border-slate-200 bg-slate-100 text-slate-900 shadow-sm shrink-0`}>
      {hasLogo ? (
        <img
          src={siteLogo}
          alt={siteName || 'store-logo'}
          className="h-full w-full object-cover"
          loading="lazy"
          decoding="async"
          onError={() => setIsBroken(true)}
        />
      ) : (
        <span className="h-full w-full inline-flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-cyan-700 text-white font-black text-lg">{letter}</span>
      )}
    </div>
  );
};

const FloatingWhatsAppButton = ({ phoneNumber, facebookUrl, instagramUrl, transition }) => {
  const normalizedWhatsapp = normalizeWhatsappNumber(phoneNumber);
  const message = encodeURIComponent(TEXT.whatsappMessage);

  const socialItems = [
    normalizedWhatsapp
      ? {
          key: 'whatsapp',
          href: `https://wa.me/${normalizedWhatsapp}?text=${message}`,
          label: TEXT.whatsapp,
          title: TEXT.whatsappTitle,
          icon: MessageCircle,
          className: 'from-emerald-500 to-teal-500 shadow-[0_20px_35px_rgba(16,185,129,0.35)]',
        }
      : null,
    String(instagramUrl || '').trim()
      ? {
          key: 'instagram',
          href: String(instagramUrl).trim(),
          label: TEXT.instagram,
          title: TEXT.instagram,
          icon: Instagram,
          className: 'from-fuchsia-500 to-rose-500 shadow-[0_20px_35px_rgba(225,29,72,0.28)]',
        }
      : null,
    String(facebookUrl || '').trim()
      ? {
          key: 'facebook',
          href: String(facebookUrl).trim(),
          label: TEXT.facebook,
          title: TEXT.facebook,
          icon: Facebook,
          className: 'from-blue-600 to-sky-600 shadow-[0_20px_35px_rgba(37,99,235,0.3)]',
        }
      : null,
  ].filter(Boolean);

  if (socialItems.length === 0) return null;

  return (
    <div className="fixed left-4 md:left-6 bottom-24 md:bottom-7 z-50 flex flex-col gap-2">
      {socialItems.map((item, index) => {
        const Icon = item.icon;
        return (
          <Motion.a
            key={item.key}
            href={item.href}
            target="_blank"
            rel="noopener noreferrer"
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...transition, delay: index * 0.05 }}
            className={`inline-flex items-center gap-2 rounded-full bg-gradient-to-l px-3.5 py-2.5 text-white transition hover:scale-[1.04] ${item.className}`}
            aria-label={item.title}
            title={item.title}
          >
            <Icon size={18} />
            <span className="text-[11px] md:text-xs font-black">{item.label}</span>
          </Motion.a>
        );
      })}
    </div>
  );
};

const DesktopNavbar = ({
  currentRoute,
  navigateTo,
  cartCount,
  isAdminAuth,
  isCartAnimating,
  onAdminLogout,
  siteName,
  siteLogo,
  searchQuery,
  setSearchQuery,
  favoritesCount,
  customerOrdersCount,
  routes,
}) => (
  <div className="hidden md:block sticky top-0 z-50 border-b border-white/35 bg-[rgba(255,255,255,0.78)] backdrop-blur-2xl shadow-[0_14px_42px_rgba(15,23,42,0.08)]">
    <div className="max-w-[1380px] mx-auto px-6 h-[86px] flex justify-between items-center gap-5">
      <button type="button" className="flex items-center gap-3 shrink-0 min-w-0" onClick={() => navigateTo(routes.home)}>
        <StoreLogo siteName={siteName} siteLogo={siteLogo} className="h-12 w-12 rounded-2xl" />
        <div className="min-w-0 text-right">
          <span className="text-xl font-black text-slate-900 tracking-tight block line-clamp-1">{siteName}</span>
          <span className="text-[11px] font-black text-slate-400 inline-flex items-center gap-1 line-clamp-1"><Sparkles size={12} /> {TEXT.subtitlePrefix + siteName}</span>
        </div>
      </button>

      <div className="flex-1 max-w-xl relative">
        <Search className="absolute right-4 top-1/2 transform -translate-y-1/2 text-slate-400" size={18} />
        <input
          type="text"
          value={searchQuery}
          onFocus={() => {
            if (currentRoute !== routes.home && currentRoute !== routes.offers) navigateTo(routes.home);
          }}
          onChange={(event) => setSearchQuery(event.target.value)}
          placeholder={TEXT.searchPlaceholder}
          className="w-full rounded-2xl border border-slate-200 bg-white py-3.5 pr-12 pl-4 outline-none focus:ring-4 focus:ring-cyan-100 focus:border-cyan-400 transition text-sm font-black"
        />
      </div>

      <div className="flex items-center gap-2.5 shrink-0">
        <button
          type="button"
          onClick={() => navigateTo(routes.home)}
          className={`inline-flex items-center gap-1 rounded-full px-3 py-2 text-sm font-black transition ${currentRoute === routes.home ? 'bg-slate-900 text-white shadow-md' : 'text-slate-600 hover:bg-white'}`}
        >
          <Home size={15} /> {TEXT.home}
        </button>

        <button
          type="button"
          onClick={() => navigateTo(routes.offers)}
          className={`inline-flex items-center gap-1 rounded-full px-3 py-2 text-sm font-black transition ${currentRoute === routes.offers ? 'bg-rose-500 text-white shadow-md' : 'text-slate-600 hover:bg-white'}`}
        >
          <BadgePercent size={15} /> {TEXT.offers}
        </button>

        <button
          type="button"
          onClick={() => navigateTo(routes.track)}
          className={`relative inline-flex items-center gap-1 rounded-full px-3 py-2 text-sm font-black transition ${currentRoute === routes.track ? 'bg-cyan-600 text-white shadow-md' : 'text-slate-600 hover:bg-white'}`}
        >
          <Compass size={15} /> {TEXT.track}
          {customerOrdersCount > 0 && (
            <span className="absolute -top-1 -left-1 inline-flex min-w-5 h-5 items-center justify-center rounded-full bg-amber-500 px-1 text-[10px] font-black text-white border-2 border-white">
              {customerOrdersCount > 99 ? '99+' : customerOrdersCount}
            </span>
          )}
        </button>

        <button type="button" onClick={() => navigateTo(routes.favorites)} className="relative p-2.5 text-slate-600 hover:text-rose-500 transition rounded-full hover:bg-white" title={TEXT.favorites}>
          <Heart size={22} className={favoritesCount > 0 ? 'fill-rose-100 text-rose-500' : ''} />
          {favoritesCount > 0 && <span className="absolute -top-1 -right-1 bg-rose-500 text-white text-[10px] w-5 h-5 rounded-full flex items-center justify-center font-black">{favoritesCount}</span>}
        </button>

        <button
          type="button"
          onClick={() => navigateTo(routes.cart)}
          className={`relative p-2.5 text-slate-600 hover:text-slate-900 transition rounded-full hover:bg-white ${isCartAnimating ? 'animate-cart-shake' : ''}`}
        >
          <ShoppingCart size={23} />
          {cartCount > 0 && <span className="absolute -top-1 -right-1 bg-emerald-500 text-white text-[10px] w-5 h-5 rounded-full flex items-center justify-center font-black">{cartCount}</span>}
          <AnimatePresence>
            {isCartAnimating && (
              <Motion.span
                initial={{ scale: 0.6, opacity: 0, y: 5 }}
                animate={{ scale: 1, opacity: 1, y: 0 }}
                exit={{ scale: 0.6, opacity: 0, y: 5 }}
                className="absolute -bottom-4 left-1/2 -translate-x-1/2 text-[10px] bg-emerald-500 text-white px-1.5 py-0.5 rounded-full font-black"
              >
                +1
              </Motion.span>
            )}
          </AnimatePresence>
        </button>

        {isAdminAuth ? (
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white p-1">
            <button type="button" onClick={() => navigateTo(routes.admin)} className="text-xs font-black bg-slate-900 text-white px-3 py-2 rounded-full">{TEXT.admin}</button>
            <button type="button" onClick={() => { onAdminLogout(); navigateTo(routes.home); }} className="text-rose-500 hover:bg-rose-50 p-2 rounded-full transition"><LogOut size={17} /></button>
          </div>
        ) : (
          <button type="button" onClick={() => navigateTo(routes.admin)} className="inline-flex items-center gap-2 text-xs font-black bg-slate-900 text-white px-4 py-2.5 rounded-full hover:bg-slate-800 transition shadow-md">
            <User size={14} /> {TEXT.login}
          </button>
        )}
      </div>
    </div>
  </div>
);

const MobileHeader = ({ title, siteName, siteLogo, cartCount, navigateTo, isCartAnimating, routes }) => (
  <header className="md:hidden sticky top-0 z-40 border-b border-slate-200/80 bg-white/92 backdrop-blur-xl px-4 py-3 flex justify-between items-center h-16 shadow-sm gap-3">
    <div className="inline-flex items-center gap-2 min-w-0">
      <StoreLogo siteName={siteName || title} siteLogo={siteLogo} className="h-9 w-9 rounded-xl" />
      <h1 className="text-lg font-black text-slate-900 tracking-tight line-clamp-1">{title}</h1>
    </div>
    <button type="button" onClick={() => navigateTo(routes.cart)} className={`relative p-2.5 text-slate-700 bg-slate-100 rounded-2xl border border-slate-200 ${isCartAnimating ? 'animate-cart-shake' : ''}`}>
      <ShoppingCart size={20} />
      {cartCount > 0 && <span className="absolute -top-1 -right-1 bg-rose-500 text-white text-[10px] w-4 h-4 rounded-full flex items-center justify-center font-black border-2 border-white">{cartCount}</span>}
    </button>
  </header>
);

const BottomNav = ({ currentRoute, navigateTo, cartCount, isCartAnimating, favoritesCount, customerOrdersCount, routes }) => (
  <div className="md:hidden fixed bottom-0 left-0 w-full border-t border-slate-200/80 bg-white/96 backdrop-blur-xl pb-safe pt-2 px-3 grid grid-cols-6 z-50 shadow-[0_-14px_28px_rgba(15,23,42,0.09)]">
    <button type="button" onClick={() => navigateTo(routes.home)} className={`flex flex-col items-center p-2 transition ${currentRoute === routes.home ? 'text-emerald-600' : 'text-slate-400'}`}>
      <Home size={21} className={currentRoute === routes.home ? 'fill-emerald-50' : ''} />
      <span className="text-[10px] mt-1 font-black">{TEXT.home}</span>
    </button>
    <button type="button" onClick={() => navigateTo(routes.offers)} className={`flex flex-col items-center p-2 transition ${currentRoute === routes.offers ? 'text-rose-500' : 'text-slate-400'}`}>
      <BadgePercent size={21} />
      <span className="text-[10px] mt-1 font-black">{TEXT.offers}</span>
    </button>
    <button type="button" onClick={() => navigateTo(routes.track)} className={`flex flex-col items-center p-2 relative transition ${currentRoute === routes.track ? 'text-cyan-600' : 'text-slate-400'}`}>
      <Compass size={21} />
      {customerOrdersCount > 0 && <span className="absolute top-1 right-4 bg-amber-500 text-white text-[10px] min-w-4 h-4 px-1 rounded-full flex items-center justify-center font-black border-2 border-white">{customerOrdersCount > 99 ? '99+' : customerOrdersCount}</span>}
      <span className="text-[10px] mt-1 font-black">{TEXT.track}</span>
    </button>
    <button type="button" onClick={() => navigateTo(routes.favorites)} className={`flex flex-col items-center p-2 relative transition ${currentRoute === routes.favorites ? 'text-rose-500' : 'text-slate-400'}`}>
      <Heart size={21} className={currentRoute === routes.favorites ? 'fill-rose-100' : ''} />
      {favoritesCount > 0 && <span className="absolute top-1 right-4 bg-rose-500 text-white text-[10px] w-4 h-4 rounded-full flex items-center justify-center font-black border-2 border-white">{favoritesCount}</span>}
      <span className="text-[10px] mt-1 font-black">{TEXT.favorites}</span>
    </button>
    <button type="button" onClick={() => navigateTo(routes.cart)} className={`flex flex-col items-center p-2 relative transition ${isCartAnimating ? 'animate-cart-shake' : ''} ${currentRoute === routes.cart || currentRoute === routes.checkout ? 'text-emerald-600' : 'text-slate-400'}`}>
      <ShoppingBag size={21} className={currentRoute === routes.cart ? 'fill-emerald-50' : ''} />
      {cartCount > 0 && <span className="absolute top-1 right-4 bg-emerald-500 text-white text-[10px] w-4 h-4 rounded-full flex items-center justify-center font-black border-2 border-white">{cartCount}</span>}
      <span className="text-[10px] mt-1 font-black">{TEXT.cart}</span>
    </button>
    <button type="button" onClick={() => navigateTo(routes.admin)} className={`flex flex-col items-center p-2 transition ${currentRoute === routes.admin ? 'text-cyan-600' : 'text-slate-400'}`}>
      <User size={21} />
      <span className="text-[10px] mt-1 font-black">{TEXT.account}</span>
    </button>
  </div>
);

const StoreFooter = ({ siteName, siteLogo, navigateTo, routes }) => (
  <footer className="mt-10 border-t border-slate-200/80 bg-white/70 backdrop-blur">
    <div className="max-w-[1380px] mx-auto px-4 md:px-6 py-8 grid grid-cols-1 md:grid-cols-3 gap-6 items-start">
      <div className="flex items-start gap-3">
        <StoreLogo siteName={siteName} siteLogo={siteLogo} className="h-11 w-11 rounded-2xl" />
        <div>
          <h3 className="text-xl font-black text-slate-900">{siteName}</h3>
          <p className="text-sm font-black text-slate-500 mt-2">{TEXT.footerDesc}</p>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <button type="button" onClick={() => navigateTo(routes.home)} className="shop-btn-soft justify-start">{TEXT.home}</button>
        <button type="button" onClick={() => navigateTo(routes.offers)} className="shop-btn-soft justify-start">{TEXT.offers}</button>
        <button type="button" onClick={() => navigateTo(routes.track)} className="shop-btn-soft justify-start">{TEXT.trackOrder}</button>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-black text-slate-500">{TEXT.note}</p>
        <p className="text-sm font-black text-slate-700 mt-1">{TEXT.footerNote}</p>
      </div>
    </div>
  </footer>
);

export { AnnouncementBar, BottomNav, DesktopNavbar, FloatingWhatsAppButton, MobileHeader, StoreFooter };
