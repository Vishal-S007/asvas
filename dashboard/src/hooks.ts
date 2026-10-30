import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";

export interface Loadable<T> { data: T | undefined; error: ApiError | undefined; loading: boolean; reload: () => void }

/** Fetch a resource, optionally re-polling. Stale data stays visible while refreshing. */
export function useResource<T>(path: string | null, pollMs = 0): Loadable<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const load = useCallback(async () => {
    if (!path) return;
    const my = ++seq.current;
    try {
      const d = await api<T>(path);
      if (my === seq.current) { setData(d); setError(undefined); }
    } catch (e) {
      if (my === seq.current) setError(e instanceof ApiError ? e : new ApiError(0, String(e)));
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    setLoading(true); setData(undefined); setError(undefined);
    void load();
    if (!pollMs) return;
    const t = setInterval(() => { if (document.visibilityState === "visible") void load(); }, pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);
  return { data, error, loading, reload: load };
}
