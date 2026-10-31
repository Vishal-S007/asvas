import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, tokenStore } from "./api";

export interface Loadable<T> { data: T | undefined; error: ApiError | undefined; loading: boolean; reload: () => void }

/** Fetch a resource, optionally re-polling. Stale data stays visible while refreshing. */
export function useResource<T>(path: string | null, pollMs = 0, refreshKey = 0): Loadable<T> {
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
  useEffect(() => { if (refreshKey) void load(); }, [refreshKey, load]);
  useEffect(() => {
    setLoading(true); setData(undefined); setError(undefined);
    void load();
    if (!pollMs) return;
    const t = setInterval(() => { if (document.visibilityState === "visible") void load(); }, pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);
  return { data, error, loading, reload: load };
}

export type StreamState = "connecting" | "live" | "ended" | "error";

/** Subscribe to a server-sent-event endpoint using fetch streaming (keeps the bearer token out of URLs).
 *  Reconnects with Last-Event-ID; stops on an `end` event or unmount. Returns a counter that bumps on each event. */
export function useEventStream(path: string | null): { tick: number; state: StreamState } {
  const [tick, setTick] = useState(0);
  const [state, setState] = useState<StreamState>("connecting");
  useEffect(() => {
    if (!path) return;
    const ctl = new AbortController();
    let lastId = "", ended = false, timer: ReturnType<typeof setTimeout> | undefined;
    const connect = async () => {
      setState("connecting");
      try {
        const headers: Record<string, string> = {};
        const t = tokenStore.get();
        if (t) headers.Authorization = `Bearer ${t}`;
        if (lastId) headers["Last-Event-ID"] = lastId;
        const res = await fetch(`/api/v1${path}`, { headers, signal: ctl.signal });
        if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
        setState("live");
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let i;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const block = buf.slice(0, i); buf = buf.slice(i + 2);
            let ev = "", id = "";
            for (const line of block.split("\n")) {
              if (line.startsWith("event: ")) ev = line.slice(7);
              else if (line.startsWith("id: ")) id = line.slice(4);
            }
            if (id) lastId = id;
            if (ev === "end") { ended = true; setState("ended"); }
            if (ev) setTick((n) => n + 1);
          }
        }
      } catch {
        if (ctl.signal.aborted) return;
        setState("error");
      }
      if (!ended && !ctl.signal.aborted) timer = setTimeout(connect, 3000);
    };
    void connect();
    return () => { ctl.abort(); if (timer) clearTimeout(timer); };
  }, [path]);
  return { tick, state };
}
