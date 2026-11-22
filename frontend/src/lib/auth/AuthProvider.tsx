import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { setAuthTokenProvider, setRefreshHandler } from "@/lib/api/client";
import {
  loginRequest,
  logoutRequest,
  meRequest,
  refreshRequest,
  type CurrentUser,
} from "@/lib/auth/authApi";
import { AuthContext, type AuthContextValue, type AuthStatus } from "@/lib/auth/authContext";
import { clearAccessToken, getAccessToken, setAccessToken } from "@/lib/auth/tokenStore";

/** Refresh this many seconds before the access token actually expires. */
const REFRESH_SKEW_SECONDS = 60;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [user, setUser] = useState<CurrentUser | null>(null);

  const timerRef = useRef<number | null>(null);
  const refreshInFlight = useRef<Promise<boolean> | null>(null);
  const silentRefreshRef = useRef<() => Promise<boolean>>(async () => false);

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const schedule = useCallback(
    (expiresInSeconds: number) => {
      clearTimer();
      const delayMs = Math.max(expiresInSeconds - REFRESH_SKEW_SECONDS, 5) * 1000;
      timerRef.current = window.setTimeout(() => {
        void silentRefreshRef.current();
      }, delayMs);
    },
    [clearTimer],
  );

  // Single-flight silent refresh. Shared by bootstrap, the proactive timer, and
  // the API client's 401 retry, so concurrent callers never stampede the endpoint.
  const silentRefresh = useCallback(async (): Promise<boolean> => {
    if (refreshInFlight.current) return refreshInFlight.current;
    const run = (async () => {
      try {
        const result = await refreshRequest();
        setAccessToken(result.access_token, result.expires_in);
        schedule(result.expires_in);
        return true;
      } catch {
        clearAccessToken();
        clearTimer();
        setUser(null);
        setStatus("anonymous");
        return false;
      } finally {
        refreshInFlight.current = null;
      }
    })();
    refreshInFlight.current = run;
    return run;
  }, [schedule, clearTimer]);
  silentRefreshRef.current = silentRefresh;

  const login = useCallback(
    async (email: string, password: string) => {
      const result = await loginRequest(email, password);
      setAccessToken(result.access_token, result.expires_in);
      try {
        const me = await meRequest();
        setUser(me);
        setStatus("authenticated");
        schedule(result.expires_in);
      } catch (error) {
        clearAccessToken();
        clearTimer();
        setStatus("anonymous");
        throw error;
      }
    },
    [schedule, clearTimer],
  );

  const logout = useCallback(async () => {
    clearTimer();
    try {
      await logoutRequest();
    } catch {
      // Best-effort: the session may already be gone. Local state is cleared either way.
    } finally {
      clearAccessToken();
      setUser(null);
      setStatus("anonymous");
    }
  }, [clearTimer]);

  const hasRole = useCallback(
    (role: string) => user?.roles.includes(role) ?? false,
    [user],
  );

  // Wire the client hooks and attempt a silent sign-in from the refresh cookie.
  useEffect(() => {
    setAuthTokenProvider(getAccessToken);
    setRefreshHandler(silentRefresh);
    let active = true;

    void (async () => {
      const ok = await silentRefresh();
      if (!active || !ok) return;
      try {
        const me = await meRequest();
        if (!active) return;
        setUser(me);
        setStatus("authenticated");
      } catch {
        if (!active) return;
        clearAccessToken();
        clearTimer();
        setStatus("anonymous");
      }
    })();

    return () => {
      active = false;
      clearTimer();
      setAuthTokenProvider(() => null);
      setRefreshHandler(null);
    };
  }, [silentRefresh, clearTimer]);

  const value = useMemo<AuthContextValue>(
    () => ({ status, user, login, logout, hasRole }),
    [status, user, login, logout, hasRole],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
