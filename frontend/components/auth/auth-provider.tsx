"use client";

import { useQueryClient } from "@tanstack/react-query";
import type { User } from "@supabase/supabase-js";
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { redeemStoredClaims } from "@/lib/claims";
import { getSupabase, isAuthConfigured } from "@/lib/supabase";

interface AuthState {
  user: User | null;
  loading: boolean;
}

const AuthContext = createContext<AuthState>({ user: null, loading: false });

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(isAuthConfigured);
  const queryClient = useQueryClient();
  const userId = user?.id ?? null;
  const previousUserId = useRef<string | null | undefined>(undefined);

  useEffect(() => {
    // Fires once with the current session, then on every change, including other tabs.
    const subscription = getSupabase()?.auth.onAuthStateChange(
      (_event, session) => {
        setUser(session?.user ?? null);
        setLoading(false);
      },
    );
    return () => subscription?.data.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (loading) return;
    const previous = previousUserId.current;
    previousUserId.current = userId;
    if (previous === userId) return;

    // Security: reset, not just refetch, so a report loaded for one account isn't left in
    // memory for whoever uses this browser next.
    if (previous !== undefined) {
      void queryClient.resetQueries({ queryKey: ["scan"] });
    }
    // This runs here rather than in the auth callback, because Supabase deadlocks if its
    // own methods are awaited from inside that callback.
    if (userId) {
      redeemStoredClaims()
        .then((claimed) => {
          if (claimed.length > 0) {
            void queryClient.invalidateQueries({ queryKey: ["scan"] });
          }
        })
        .catch(() => {
          // The tokens are kept, so the next page load tries again.
        });
    }
  }, [loading, userId, queryClient]);

  const value = useMemo(() => ({ user, loading }), [user, loading]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
