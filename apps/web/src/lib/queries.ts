import {
  type QueryClient,
  queryOptions,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { redirect } from "@tanstack/react-router";
import { ApiRequestError, api } from "./api";
import { clearSession, setSession } from "./auth";
import type { MeResponse, MeUser, TenantListItem } from "./types";

export const meQueryOptions = queryOptions({
  queryKey: ["me"],
  queryFn: () => api<MeResponse>("/api/auth/me"),
  staleTime: 5 * 60_000,
  retry: false,
});

export const tenantsQueryOptions = queryOptions({
  queryKey: ["tenants"],
  queryFn: () => api<TenantListItem[]>("/api/tenants"),
  staleTime: 30_000,
});

/** Route guard: resolves the session once (cached) or redirects to /login on 401. */
export async function requireAuth(queryClient: QueryClient): Promise<MeResponse> {
  try {
    return await queryClient.ensureQueryData(meQueryOptions);
  } catch (e) {
    if (e instanceof ApiRequestError && e.status === 401) throw redirect({ to: "/login" });
    throw e;
  }
}

export function useMe() {
  return useQuery(meQueryOptions);
}

export function useTenants() {
  return useQuery(tenantsQueryOptions);
}

export function useCreateTenant() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string; slug: string }) =>
      api<TenantListItem>("/api/tenants", { method: "POST", body: input }),
    onSuccess: async () => {
      // The sidebar resolves tenants from /me, so both lists go stale.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: tenantsQueryOptions.queryKey }),
        queryClient.invalidateQueries({ queryKey: meQueryOptions.queryKey }),
      ]);
    },
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { email: string; password: string }) =>
      api<{ user: MeUser; csrfToken: string }>("/api/auth/login", { method: "POST", body: input }),
    onSuccess: (session) => {
      queryClient.clear();
      setSession(session);
    },
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api<void>("/api/auth/logout", { method: "POST" }),
    onSettled: () => {
      clearSession();
      queryClient.clear();
    },
  });
}

export function useJwksHealth(slug: string) {
  return useQuery({
    queryKey: ["jwks-health", { slug }],
    queryFn: async () => (await fetch(`/t/${encodeURIComponent(slug)}/.well-known/jwks.json`)).ok,
    refetchInterval: 60_000,
    retry: false,
  });
}
