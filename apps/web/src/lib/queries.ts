import type {
  ApplicationDto,
  ApplicationKeyDto,
  ApprovalCountsDto,
  ApprovalDto,
  MemberDto,
  ResourceDto,
  ScopeDto,
  SigningKeyDto,
  TaskSummaryDto,
  TenantDto,
  TenantRole,
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
      // Pending/settled mutations hold the previous user's variables (e.g. one-time secrets).
      queryClient.getMutationCache().clear();
    },
  });
}

export function useJwksHealth({ slug, issuer }: { slug: string; issuer: string }) {
  // Probe the issuer only when it is same-origin: the browser may not reach PUBLIC_URL (internal
  // hostname, split DNS, CORS), whereas the relative path always hits the API serving this UI.
  const url =
    new URL(issuer, window.location.href).origin === window.location.origin
      ? `${issuer}/.well-known/jwks.json`
      : `/t/${encodeURIComponent(slug)}/.well-known/jwks.json`;
  return useQuery({
    queryKey: ["jwks-health", { url }],
    queryFn: async () => (await fetch(url)).ok,
    refetchInterval: 60_000,
    retry: false,
  });
}

// --- token events (Task 4.4)
export type TokenEventParams = {
  outcome?: "issued" | "denied" | "revoked";
  applicationId?: string;
  taskId?: string;
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
  agentBudgetUsed: number | null;
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
    refetchInterval: (query) => (query.state.data?.application.kind === "agent" ? 5000 : false),
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
  const queryClient = useQueryClient();
  const invalidateApps = useApplicationInvalidate(tenantId);
  // Resource pages show granted-app counts, so they go stale too.
  const invalidate = () =>
    Promise.all([
      invalidateApps(),
      queryClient.invalidateQueries({ queryKey: ["resources", { tenantId }] }),
      queryClient.invalidateQueries({ queryKey: ["resource", { tenantId }] }),
    ]);
  return useMutation({
    mutationFn: (scopeIds: string[]) =>
      api<{ grants: GrantView[] }>(`/api/tenants/${tenantId}/applications/${appId}/grants`, {
        method: "PUT",
        body: { scopeIds },
      }),
    onSuccess: invalidate,
  });
}

// --- resources (Task 4.3)
export type ResourceListItem = ResourceDto & {
  scopeCount: number;
  appCount: number;
  tokens24h: number;
};
export type ResourceDetail = ResourceDto & {
  scopes: (ScopeDto & { grantedAppCount: number })[];
  applications: { id: string; name: string; clientId: string }[];
};
type ResourceInput = { name: string; kind?: "api" | "mcp"; audience: string };
export type ResourceCreateBody = ResourceInput & { tokenTtlSeconds?: number };
export type ResourceUpdateBody = Partial<ResourceInput> & { tokenTtlSeconds?: number | null };
type ScopeBody = {
  name?: string;
  description?: string | null;
  agentPolicy?: ScopeDto["agentPolicy"];
};

export function useResources(tenantId: string) {
  return useQuery({
    queryKey: ["resources", { tenantId }],
    queryFn: () => api<ResourceListItem[]>(`/api/tenants/${tenantId}/resources`),
  });
}

export function useResource(tenantId: string, resourceId: string | undefined) {
  return useQuery({
    queryKey: ["resource", { tenantId, resourceId }],
    queryFn: () => api<ResourceDetail>(`/api/tenants/${tenantId}/resources/${resourceId}`),
    enabled: !!resourceId,
  });
}

/** Every resources/scopes mutation invalidates the resource caches and the application caches (grants embed resource/scope names). */
function useResourceMutation<V, R>(tenantId: string, fn: (v: V) => Promise<R>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["resources", { tenantId }] }),
        queryClient.invalidateQueries({ queryKey: ["resource", { tenantId }] }),
        queryClient.invalidateQueries({ queryKey: ["application", { tenantId }] }),
        queryClient.invalidateQueries({ queryKey: ["applications", { tenantId }] }),
      ]);
    },
  });
}

export function useCreateResource(tenantId: string) {
  return useResourceMutation(tenantId, (body: ResourceCreateBody) =>
    api<ResourceDto>(`/api/tenants/${tenantId}/resources`, { method: "POST", body }),
  );
}

export function useUpdateResource(tenantId: string) {
  return useResourceMutation(tenantId, (v: { id: string; body: ResourceUpdateBody }) =>
    api<ResourceDto>(`/api/tenants/${tenantId}/resources/${v.id}`, {
      method: "PATCH",
      body: v.body,
    }),
  );
}

export function useDeleteResource(tenantId: string) {
  return useResourceMutation(tenantId, (id: string) =>
    api<void>(`/api/tenants/${tenantId}/resources/${id}`, { method: "DELETE" }),
  );
}

export function useCreateScope(tenantId: string, resourceId: string) {
  return useResourceMutation(
    tenantId,
    (body: { name: string; description?: string; agentPolicy?: ScopeDto["agentPolicy"] }) =>
      api<ScopeDto>(`/api/tenants/${tenantId}/resources/${resourceId}/scopes`, {
        method: "POST",
        body,
      }),
  );
}

export function useUpdateScope(tenantId: string, resourceId: string) {
  return useResourceMutation(tenantId, (v: { id: string; body: ScopeBody }) =>
    api<ScopeDto>(`/api/tenants/${tenantId}/resources/${resourceId}/scopes/${v.id}`, {
      method: "PATCH",
      body: v.body,
    }),
  );
}

export function useDeleteScope(tenantId: string, resourceId: string) {
  return useResourceMutation(tenantId, (id: string) =>
    api<void>(`/api/tenants/${tenantId}/resources/${resourceId}/scopes/${id}`, {
      method: "DELETE",
    }),
  );
}

// --- settings (Task 4.5)
export type TenantDetail = TenantDto & {
  discoveryUrl: string;
  jwksUrl: string;
  role: TenantRole;
};

export type TenantPatch = {
  name?: string;
  defaultTokenTtlSeconds?: number;
  introspectionEnabled?: boolean;
  keyRotationDays?: number | null;
};

export function useTenant(tenantId: string) {
  return useQuery({
    queryKey: ["tenant", { tenantId }],
    queryFn: () => api<TenantDetail>(`/api/tenants/${tenantId}`),
  });
}

/** Tenant-level mutations change /me (names, sidebar) and the tenants list too. */
function useInvalidateTenant(tenantId: string) {
  const queryClient = useQueryClient();
  return () =>
    Promise.all(
      [["tenant", { tenantId }], ["me"], ["tenants"]].map((queryKey) =>
        queryClient.invalidateQueries({ queryKey }),
      ),
    );
}

export function useUpdateTenant(tenantId: string) {
  const invalidate = useInvalidateTenant(tenantId);
  return useMutation({
    mutationFn: (patch: TenantPatch) =>
      api<TenantDto>(`/api/tenants/${tenantId}`, { method: "PATCH", body: patch }),
    onSuccess: invalidate,
  });
}

export function useTenantAction(
  tenantId: string,
  action: "pause" | "resume" | "revoke-all-tokens",
) {
  const invalidate = useInvalidateTenant(tenantId);
  return useMutation({
    mutationFn: () => api<unknown>(`/api/tenants/${tenantId}/${action}`, { method: "POST" }),
    onSuccess: invalidate,
  });
}

export function useDeleteTenant(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (confirmSlug: string) =>
      api<void>(`/api/tenants/${tenantId}`, { method: "DELETE", body: { confirmSlug } }),
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: ["tenant", { tenantId }] });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["me"] }),
        queryClient.invalidateQueries({ queryKey: ["tenants"] }),
      ]);
    },
  });
}

export function useSigningKeys(tenantId: string) {
  return useQuery({
    queryKey: ["signing-keys", { tenantId }],
    queryFn: async () =>
      (await api<{ items: SigningKeyDto[] }>(`/api/tenants/${tenantId}/signing-keys`)).items,
  });
}

export function useRotateKey(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<SigningKeyDto>(`/api/tenants/${tenantId}/signing-keys/rotate`, { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["signing-keys", { tenantId }] }),
  });
}

export function useMembers(tenantId: string) {
  return useQuery({
    queryKey: ["members", { tenantId }],
    queryFn: () => api<MemberDto[]>(`/api/tenants/${tenantId}/members`),
  });
}

function useInvalidateMembers(tenantId: string) {
  const queryClient = useQueryClient();
  return () => queryClient.invalidateQueries({ queryKey: ["members", { tenantId }] });
}

export function useAddMember(tenantId: string) {
  const invalidate = useInvalidateMembers(tenantId);
  return useMutation({
    mutationFn: (input: { email: string; name?: string; role: TenantRole }) =>
      api<{ member: MemberDto; temporaryPassword?: string }>(`/api/tenants/${tenantId}/members`, {
        method: "POST",
        body: input,
      }),
    onSuccess: invalidate,
  });
}

export function useUpdateMemberRole(tenantId: string) {
  const invalidate = useInvalidateMembers(tenantId);
  return useMutation({
    mutationFn: (input: { adminUserId: string; role: TenantRole }) =>
      api<MemberDto>(`/api/tenants/${tenantId}/members/${input.adminUserId}`, {
        method: "PATCH",
        body: { role: input.role },
      }),
    onSuccess: invalidate,
  });
}

export function useRemoveMember(tenantId: string) {
  const invalidate = useInvalidateMembers(tenantId);
  return useMutation({
    mutationFn: (adminUserId: string) =>
      api<void>(`/api/tenants/${tenantId}/members/${adminUserId}`, { method: "DELETE" }),
    onSuccess: invalidate,
  });
}

// --- tokens: recent tasks (Task 6.6)
export function useTasks(
  tenantId: string,
  { applicationId, limit }: { applicationId?: string; limit?: number } = {},
) {
  return useQuery({
    queryKey: ["tasks", { tenantId, applicationId }],
    queryFn: () => {
      const sp = new URLSearchParams();
      if (applicationId) sp.set("applicationId", applicationId);
      if (limit) sp.set("limit", String(limit));
      return api<{ items: TaskSummaryDto[] }>(`/api/tenants/${tenantId}/token-events/tasks?${sp}`);
    },
    refetchInterval: 5000,
    select: (d) => d.items,
  });
}

/** Ids of agent applications, for the events table Agent column (the event DTO carries no kind). */
export function useAgentAppIds(tenantId: string) {
  return useQuery({
    queryKey: ["token-app-kinds", { tenantId }],
    queryFn: () =>
      api<{ items: { id: string; kind: "service" | "agent" }[] }>(
        `/api/tenants/${tenantId}/applications`,
      ),
    staleTime: 30_000,
    select: (d) => new Set(d.items.filter((a) => a.kind === "agent").map((a) => a.id)),
  });
}

// --- applications: keys + agents (Tasks 6.1/6.2)
export type AgentFields = {
  agentRuntime?: string | null;
  operatorEmail?: string | null;
  allowedCidrs?: string[];
  maxScopesPerToken?: number | null;
  tokenBudgetPerHour?: number | null;
};
export type ApplicationWriteInput = AgentFields & {
  tokenEndpointAuthMethod?: ApplicationDto["tokenEndpointAuthMethod"];
  tokenTtlSeconds?: number | null;
};

/** Like useApplicationsList, with the `kind` filter. */
export function useApplicationsListByKind(
  tenantId: string,
  filters: { q: string; status?: ApplicationStatusFilter; kind?: "service" | "agent" },
) {
  return useQuery({
    queryKey: ["applications", { tenantId, ...filters }],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filters.q) params.set("q", filters.q);
      if (filters.status) params.set("status", filters.status);
      if (filters.kind) params.set("kind", filters.kind);
      const qs = params.size ? `?${params}` : "";
      return (
        await api<{ items: ApplicationListItem[] }>(`/api/tenants/${tenantId}/applications${qs}`)
      ).items;
    },
    placeholderData: keepPreviousData,
  });
}

/** Create accepting `kind` and the agent fields. */
export function useApplicationCreateWithKind(tenantId: string) {
  const invalidate = useApplicationInvalidate(tenantId);
  return useMutation({
    mutationFn: (
      input: ApplicationWriteInput & {
        name: string;
        description?: string;
        kind?: "service" | "agent";
      },
    ) =>
      api<{ application: ApplicationDto; clientSecret: string }>(
        `/api/tenants/${tenantId}/applications`,
        { method: "POST", body: input },
      ),
    onSuccess: invalidate,
  });
}

/** PATCH accepting the agent fields. */
export function useApplicationPatch(tenantId: string, appId: string) {
  const invalidate = useApplicationInvalidate(tenantId);
  return useMutation({
    mutationFn: (input: ApplicationWriteInput) =>
      api<ApplicationDto>(`/api/tenants/${tenantId}/applications/${appId}`, {
        method: "PATCH",
        body: input,
      }),
    onSuccess: invalidate,
  });
}

export function useApplicationKeys(tenantId: string, appId: string) {
  return useQuery({
    queryKey: ["application-keys", { tenantId, appId }],
    queryFn: async () =>
      (
        await api<{ items: ApplicationKeyDto[] }>(
          `/api/tenants/${tenantId}/applications/${appId}/keys`,
        )
      ).items,
  });
}

function useKeyInvalidate(tenantId: string, appId: string) {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["application-keys", { tenantId, appId }] }),
      queryClient.invalidateQueries({ queryKey: ["application", { tenantId, appId }] }),
    ]);
}

export function useRegisterApplicationKey(tenantId: string, appId: string) {
  const invalidate = useKeyInvalidate(tenantId, appId);
  return useMutation({
    mutationFn: (input: { kid: string; publicKeyPem: string }) =>
      api<ApplicationKeyDto>(`/api/tenants/${tenantId}/applications/${appId}/keys`, {
        method: "POST",
        body: input,
      }),
    onSuccess: invalidate,
  });
}

export function useRetireApplicationKey(tenantId: string, appId: string) {
  const invalidate = useKeyInvalidate(tenantId, appId);
  return useMutation({
    mutationFn: (keyId: string) =>
      api<ApplicationKeyDto>(
        `/api/tenants/${tenantId}/applications/${appId}/keys/${keyId}/retire`,
        {
          method: "POST",
          body: {},
        },
      ),
    onSuccess: invalidate,
  });
}

export function useDeleteApplicationKey(tenantId: string, appId: string) {
  const invalidate = useKeyInvalidate(tenantId, appId);
  return useMutation({
    mutationFn: (keyId: string) =>
      api<void>(`/api/tenants/${tenantId}/applications/${appId}/keys/${keyId}`, {
        method: "DELETE",
      }),
    onSuccess: invalidate,
  });
}

// --- approvals (Task 6.3)
type ApprovalList = { items: ApprovalDto[]; nextCursor: string | null; counts: ApprovalCountsDto };

export function useApprovals(tenantId: string, status: "pending" | "resolved") {
  return useInfiniteQuery({
    queryKey: ["approvals", { tenantId, status }],
    queryFn: ({ pageParam }) => {
      const sp = new URLSearchParams({ status });
      if (pageParam) sp.set("cursor", pageParam);
      return api<ApprovalList>(`/api/tenants/${tenantId}/approvals?${sp}`);
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: 10_000,
  });
}

export function useApprovalCounts(tenantId: string) {
  return useQuery({
    queryKey: ["approval-counts", { tenantId }],
    queryFn: () => api<ApprovalList>(`/api/tenants/${tenantId}/approvals?status=pending&limit=1`),
    select: (d) => d.counts,
    refetchInterval: 30_000,
  });
}

export function useDecideApproval(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (v: { id: string; action: "approve" | "deny" }) =>
      api<ApprovalDto>(`/api/tenants/${tenantId}/approvals/${v.id}/${v.action}`, {
        method: "POST",
      }),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: ["approvals", { tenantId }] }),
        queryClient.invalidateQueries({ queryKey: ["approval-counts", { tenantId }] }),
      ]),
  });
}
