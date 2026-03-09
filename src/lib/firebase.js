import { getApp, getApps, initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

const hasFirebaseConfig = Object.values(firebaseConfig).every(
  (value) => typeof value === 'string' && value.trim() !== '',
);

const firebaseApp = hasFirebaseConfig
  ? getApps().length > 0
    ? getApp()
    : initializeApp(firebaseConfig)
  : null;

const db = firebaseApp ? getFirestore(firebaseApp) : null;
const auth = firebaseApp ? getAuth(firebaseApp) : null;

export { auth, hasFirebaseConfig, db };
