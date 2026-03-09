import { useEffect, useState } from 'react';
import { loadAlgeriaLocations } from '../utils/algeriaLocations';

const EMPTY_LOCATIONS = {
  wilayaOptions: [],
  communesByWilaya: {},
  defaultWilayaCode: '',
};

const useAlgeriaLocations = (enabled) => {
  const [locations, setLocations] = useState(EMPTY_LOCATIONS);
  const [isLoading, setIsLoading] = useState(Boolean(enabled));
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;

    if (!enabled) {
      setIsLoading(false);
      return undefined;
    }

    const run = async () => {
      try {
        setIsLoading(true);
        setError('');
        const loaded = await loadAlgeriaLocations();
        if (!active) return;
        setLocations(loaded);
      } catch {
        if (!active) return;
        setError('تعذر تحميل قائمة الولايات والبلديات.');
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    };

    run();

    return () => {
      active = false;
    };
  }, [enabled]);

  return {
    locations,
    isLoading,
    error,
  };
};

export { EMPTY_LOCATIONS, useAlgeriaLocations };
