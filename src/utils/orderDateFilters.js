const DAY_IN_MS = 24 * 60 * 60 * 1000;

const normalizeDateValue = (value) => {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
};

const startOfDay = (value) => {
  const date = normalizeDateValue(value);
  if (!date) return null;
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), 0, 0, 0, 0);
};

const endOfDay = (value) => {
  const date = normalizeDateValue(value);
  if (!date) return null;
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), 23, 59, 59, 999);
};

const parseDateInput = (value, mode = 'start') => {
  if (!value) return null;
  const [year, month, day] = String(value).split('-').map(Number);
  if (!year || !month || !day) return null;
  return mode === 'end'
    ? new Date(year, month - 1, day, 23, 59, 59, 999)
    : new Date(year, month - 1, day, 0, 0, 0, 0);
};

const startOfWeekMonday = (value) => {
  const date = startOfDay(value);
  if (!date) return null;
  const day = date.getDay();
  const distanceToMonday = day === 0 ? 6 : day - 1;
  return new Date(date.getTime() - distanceToMonday * DAY_IN_MS);
};

const getOrderDateRange = (preset, options = {}) => {
  const now = normalizeDateValue(options.now || new Date()) || new Date();
  const todayStart = startOfDay(now);
  const todayEnd = endOfDay(now);

  switch (preset) {
    case 'today':
      return { from: todayStart, to: todayEnd };
    case 'yesterday': {
      const yesterday = new Date(todayStart.getTime() - DAY_IN_MS);
      return { from: startOfDay(yesterday), to: endOfDay(yesterday) };
    }
    case 'week':
      return { from: startOfWeekMonday(now), to: todayEnd };
    case 'month':
      return {
        from: new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0),
        to: todayEnd,
      };
    case 'custom': {
      const customStart = parseDateInput(options.customStart, 'start');
      const customEnd = parseDateInput(options.customEnd, 'end');
      return { from: customStart, to: customEnd };
    }
    case 'all':
    default:
      return { from: null, to: null };
  }
};

const isWithinDateRange = (value, range) => {
  const date = normalizeDateValue(value);
  if (!date) return false;
  const fromMs = range?.from ? range.from.getTime() : Number.NEGATIVE_INFINITY;
  const toMs = range?.to ? range.to.getTime() : Number.POSITIVE_INFINITY;
  const current = date.getTime();
  return current >= fromMs && current <= toMs;
};

const toDateInputValue = (value) => {
  const date = normalizeDateValue(value);
  if (!date) return '';
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};

export { getOrderDateRange, isWithinDateRange, toDateInputValue };
