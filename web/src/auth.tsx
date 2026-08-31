import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { PropsWithChildren } from "react";
import { api, loadSession, saveSession } from "./api";
import type { StoredSession } from "./api";
import type { LoginResponse, LoginResult, UserProfile } from "./types";

interface AuthContextValue {
  session: StoredSession | null;
  user: UserProfile | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<LoginResult>;
  acceptSession: (session: LoginResponse) => Promise<UserProfile>;
  logout: () => void;
  refreshUser: () => Promise<UserProfile | null>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: PropsWithChildren) {
  const [session, setSession] = useState<StoredSession | null>(() => loadSession());
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(() => Boolean(loadSession()));

  const logout = useCallback(() => {
    // Start the server-side cookie invalidation while CSRF metadata is still
    // available, then clear local UI state regardless of network availability.
    if (loadSession()) void api.logout().catch(() => undefined);
    saveSession(null);
    setSession(null);
    setUser(null);
    setLoading(false);
  }, []);

  const refreshUser = useCallback(async () => {
    if (!loadSession()) return null;
    const nextUser = await api.me();
    setUser(nextUser);
    return nextUser;
  }, []);

  useEffect(() => {
    const handleUnauthorized = () => logout();
    window.addEventListener("bantam:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("bantam:unauthorized", handleUnauthorized);
  }, [logout]);

  useEffect(() => {
    if (!session) {
      setLoading(false);
      return;
    }
    setLoading(true);
    api
      .me()
      .then(setUser)
      .catch(logout)
      .finally(() => setLoading(false));
  }, [logout, session]);

  const acceptSession = useCallback(async (nextSession: LoginResponse) => {
    saveSession(nextSession);
    setSession(nextSession);
    const nextUser = await api.me();
    setUser(nextUser);
    return nextUser;
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const result = await api.login(email, password);
    if ("csrf_token" in result) await acceptSession(result);
    return result;
  }, [acceptSession]);

  const value = useMemo(
    () => ({
      session,
      user,
      loading,
      login,
      acceptSession,
      logout,
      refreshUser,
    }),
    [
      session,
      user,
      loading,
      login,
      acceptSession,
      logout,
      refreshUser,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used within AuthProvider");
  return value;
}
