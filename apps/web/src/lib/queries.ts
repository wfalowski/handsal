import type {
  ApplicationDto,
  ResourceDto,
  ScopeDto,
  TenantDto,
  TokenEventDto,
  TokenStatsDto,
} from "@handsal/shared";
import {
  keepPreviousData,
  type QueryClient,
  queryOptions,
  useInfiniteQuery,
  useMutation,
  useQueries,
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

// --- applications (Task 4.2)
export type ApplicationStatusFilter = "active" | "needs_attention";
export type ApplicationListItem = ApplicationDto & { resourceCount: number; scopeNames: string[] };
export type GrantView = {
  resource: { id: string; name: string; audience: string; kind: "api" | "mcp" };
  scopes: { id: string; name: string }[];
};
export type ApplicationDetail = {
  application: ApplicationDto;
  grants: GrantView[];
  issuer: string;
  tokenEndpoint: string;
  recentTokens: TokenEventDto[];
};
export type ResourceWithScopes = ResourceDto & { scopes: ScopeDto[] };

export function useApplicationsList(
  tenantId: string,
  filters: { q: string; status?: ApplicationStatusFilter },
) {
  return useQuery({
    queryKey: ["applications", { tenantId, ...filters }],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filters.q) params.set("q", filters.q);
      if (filters.status) params.set("status", filters.status);
      const qs = params.size ? `?${params}` : "";
      return (
        await api<{ items: ApplicationListItem[] }>(`/api/tenants/${tenantId}/applications${qs}`)
      ).items;
    },
    placeholderData: keepPreviousData,
  });
}

export function useApplicationDetail(tenantId: string, appId: string) {
  return useQuery({
    queryKey: ["application", { tenantId, appId }],
    queryFn: () => api<ApplicationDetail>(`/api/tenants/${tenantId}/applications/${appId}`),
  });
}

export function useApplicationTenantInfo(tenantId: string) {
  return useQuery({
    queryKey: ["application-tenant", { tenantId }],
    queryFn: () => api<TenantDto>(`/api/tenants/${tenantId}`),
    staleTime: 30_000,
  });
}

/** Every tenant resource with its full scope list (list + one detail fetch per resource). */
export function useGrantsResources(tenantId: string) {
  const list = useQuery({
    queryKey: ["resources", { tenantId }],
    queryFn: () => api<ResourceDto[]>(`/api/tenants/${tenantId}/resources`),
  });
  const details = useQueries({
    queries: (list.data ?? []).map((r) => ({
      queryKey: ["resources", { tenantId, resourceId: r.id }],
      queryFn: () => api<ResourceWithScopes>(`/api/tenants/${tenantId}/resources/${r.id}`),
    })),
  });
  return {
    isPending: list.isPending || details.some((d) => d.isPending),
    isError: list.isError || details.some((d) => d.isError),
    resources: details.flatMap((d) => (d.data ? [d.data] : [])),
  };
}

function useApplicationInvalidate(tenantId: string) {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["applications"] }),
      queryClient.invalidateQueries({ queryKey: ["application", { tenantId }] }),
    ]);
}

export function useApplicationCreate(tenantId: string) {
  const invalidate = useApplicationInvalidate(tenantId);
  return useMutation({
    mutationFn: (input: {
      name: string;
      description?: string;
      tokenEndpointAuthMethod?: ApplicationDto["tokenEndpointAuthMethod"];
      tokenTtlSeconds?: number;
    }) =>
      api<{ application: ApplicationDto; clientSecret: string }>(
        `/api/tenants/${tenantId}/applications`,
        { method: "POST", body: input },
      ),
    onSuccess: invalidate,
  });
}

export function useApplicationUpdate(tenantId: string, appId: string) {
  const invalidate = useApplicationInvalidate(tenantId);
  return useMutation({
    mutationFn: (input: {
      tokenEndpointAuthMethod?: ApplicationDto["tokenEndpointAuthMethod"];
      tokenTtlSeconds?: number | null;
    }) =>
      api<ApplicationDto>(`/api/tenants/${tenantId}/applications/${appId}`, {
        method: "PATCH",
        body: input,
      }),
    onSuccess: invalidate,
  });
}

export function useApplicationSetStatus(tenantId: string, appId: string) {
  const invalidate = useApplicationInvalidate(tenantId);
  return useMutation({
    mutationFn: (action: "enable" | "disable") =>
      api<ApplicationDto>(`/api/tenants/${tenantId}/applications/${appId}/${action}`, {
        method: "POST",
      }),
    onSuccess: invalidate,
  });
}

export function useApplicationDelete(tenantId: string, appId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<void>(`/api/tenants/${tenantId}/applications/${appId}`, { method: "DELETE" }),
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: ["application", { tenantId, appId }] });
      await queryClient.invalidateQueries({ queryKey: ["applications"] });
    },
  });
}

export function useApplicationRotateSecret(tenantId: string, appId: string) {
  const invalidate = useApplicationInvalidate(tenantId);
  return useMutation({
    mutationFn: (graceSeconds: number) =>
      api<{ clientSecret: string; previousSecretExpiresAt: string | null }>(
        `/api/tenants/${tenantId}/applications/${appId}/rotate-secret`,
        { method: "POST", body: { graceSeconds } },
      ),
    onSuccess: invalidate,
  });
}

export function useGrantsSave(tenantId: string, appId: string) {
  const invalidate = useApplicationInvalidate(tenantId);
  return useMutation({
    mutationFn: (scopeIds: string[]) =>
      api<{ grants: GrantView[] }>(`/api/tenants/${tenantId}/applications/${appId}/grants`, {
        method: "PUT",
        body: { scopeIds },
      }),
    onSuccess: invalidate,
  });
}
