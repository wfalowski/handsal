import type { TokenEventDto, TokenStatsDto } from "@handsal/shared";
import {
  type QueryClient,
  queryOptions,
  useInfiniteQuery,
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
  queryFn: async () => {
    const me = await api<MeResponse>("/api/auth/me");
    if (me.csrfToken) setSession({ user: me.user, csrfToken: me.csrfToken });
    return me;
  },
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

// --- token events (Task 4.4)
export type TokenEventParams = {
  outcome?: "issued" | "denied" | "revoked";
  applicationId?: string;
  q?: string;
  enabled?: boolean;
};

export function useTokenEvents(tenantId: string, { enabled, ...params }: TokenEventParams) {
  return useInfiniteQuery({
    queryKey: ["token-events", { tenantId, ...params }],
    queryFn: ({ pageParam }) => {
      const sp = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) if (v) sp.set(k, v);
      if (pageParam) sp.set("cursor", pageParam);
      return api<{ items: TokenEventDto[]; nextCursor: string | null }>(
        `/api/tenants/${tenantId}/token-events?${sp}`,
      );
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: 5000, // pauses in background tabs (refetchIntervalInBackground defaults to false)
    enabled,
  });
}

export function useTokenStats(tenantId: string) {
  return useQuery({
    queryKey: ["token-stats", { tenantId }],
    queryFn: () => api<TokenStatsDto>(`/api/tenants/${tenantId}/token-events/stats`),
    refetchInterval: 5000,
  });
}

/** applicationId -> name, for the Client column and the filter chip. */
export function useTokenApps(tenantId: string) {
  return useQuery({
    queryKey: ["token-apps", { tenantId }],
    queryFn: () =>
      api<{ items: { id: string; name: string }[] }>(`/api/tenants/${tenantId}/applications`),
    staleTime: 30_000,
    select: (d) => new Map(d.items.map((a) => [a.id, a.name])),
  });
}
