const readStorage = (key, fallbackValue) => {
  if (typeof window === 'undefined') return fallbackValue;

  try {
    const rawValue = window.localStorage.getItem(key);
    if (!rawValue) return fallbackValue;
    return JSON.parse(rawValue);
  } catch {
    return fallbackValue;
  }
};

const writeStorage = (key, value) => {
  if (typeof window === 'undefined') return;

  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // no-op
  }
};

export { readStorage, writeStorage };
