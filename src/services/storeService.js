import { doc, getDoc, serverTimestamp, setDoc } from 'firebase/firestore';
import { db, hasFirebaseConfig } from '../lib/firebase';
import { uploadImageToImgBB } from './imgbbService';

const STORE_COLLECTION = 'store_data';
const STORE_DOCS = {
  products: 'products',
  orders: 'orders',
  siteConfig: 'site_config',
};

const getStoreDocRef = (docKey) => doc(db, STORE_COLLECTION, docKey);

const readRemotePart = async (docKey, fallback) => {
  if (!hasFirebaseConfig || !db) return fallback;

  try {
    const snapshot = await getDoc(getStoreDocRef(docKey));
    if (!snapshot.exists()) return fallback;

    const payload = snapshot.data()?.value;
    return payload ?? fallback;
  } catch {
    return fallback;
  }
};

const writeRemotePart = async (docKey, value) => {
  if (!hasFirebaseConfig || !db) return;

  await setDoc(
    getStoreDocRef(docKey),
    {
      value,
      updatedAt: serverTimestamp(),
    },
    { merge: true },
  );
};

const loadStoreBundle = async ({ products, orders, siteConfig }) => {
  const [remoteProducts, remoteOrders, remoteSiteConfig] = await Promise.all([
    readRemotePart(STORE_DOCS.products, products),
    readRemotePart(STORE_DOCS.orders, orders),
    readRemotePart(STORE_DOCS.siteConfig, siteConfig),
  ]);

  return {
    products: remoteProducts,
    orders: remoteOrders,
    siteConfig: remoteSiteConfig,
  };
};

const saveProductsRemote = async (products) => writeRemotePart(STORE_DOCS.products, products);
const saveOrdersRemote = async (orders) => writeRemotePart(STORE_DOCS.orders, orders);
const saveSiteConfigRemote = async (siteConfig) => writeRemotePart(STORE_DOCS.siteConfig, siteConfig);

const uploadProductImage = async (file, options = {}) => {
  const imgbbApiKey = import.meta.env.VITE_IMGBB_API_KEY?.trim();

  const result = await uploadImageToImgBB(file, {
    apiKey: imgbbApiKey,
    onProgress: options.onProgress,
    maxSizeMb: options.maxSizeMb,
  });

  return result.imageUrl;
};

export {
  hasFirebaseConfig,
  loadStoreBundle,
  saveOrdersRemote,
  saveProductsRemote,
  saveSiteConfigRemote,
  uploadProductImage,
};
