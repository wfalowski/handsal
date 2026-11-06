import { applicationGrants, applicationKeys, applications, db, scopes } from "@handsal/db";
import type {
  ApplicationDto,
  applicationCreateSchema,
  applicationUpdateSchema,
} from "@handsal/shared";
import { and, asc, eq, gt, ilike, or, type SQL, sql } from "drizzle-orm";
import type { z } from "zod";
import { ApiError } from "../middleware/error-handler.js";
import { parseCidrs } from "../utils/cidr.js";
import { generateClientId, generateClientSecret, hashSecret } from "../utils/crypto.js";

type ApplicationRow = typeof applications.$inferSelect;
export type ApplicationCreateInput = z.infer<typeof applicationCreateSchema>;
export type ApplicationUpdateInput = z.infer<typeof applicationUpdateSchema>;
export type ApplicationListStatus = "active" | "disabled" | "needs_attention";
export type ApplicationListItem = ApplicationDto & { resourceCount: number; scopeNames: string[] };

const iso = (d: Date | null) => (d ? d.toISOString() : null);

export function toApplicationDto(row: ApplicationRow): ApplicationDto {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    kind: row.kind,
    clientId: row.clientId,
    tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
    tokenTtlSeconds: row.tokenTtlSeconds,
    status: row.status,
    secretRotatedAt: iso(row.secretRotatedAt),
    previousSecretExpiresAt: iso(row.previousSecretExpiresAt),
    tokensNotBefore: iso(row.tokensNotBefore),
    lastTokenAt: iso(row.lastTokenAt),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    agentRuntime: row.agentRuntime,
    operatorEmail: row.operatorEmail,
    allowedCidrs: row.allowedCidrs,
    maxScopesPerToken: row.maxScopesPerToken,
    tokenBudgetPerHour: row.tokenBudgetPerHour,
    mayActFor: row.mayActFor as ApplicationDto["mayActFor"], // text[] column, values validated on write
    delegationScopeMode: row.delegationScopeMode,
  };
}

const AGENT_FIELDS = [
  "agentRuntime",
  "operatorEmail",
  "allowedCidrs",
  "maxScopesPerToken",
  "tokenBudgetPerHour",
  "mayActFor",
  "delegationScopeMode",
] as const;
type AgentFieldsInput = Pick<ApplicationUpdateInput, (typeof AGENT_FIELDS)[number]>;

const hasAgentField = (input: AgentFieldsInput) => AGENT_FIELDS.some((f) => input[f] !== undefined);

/** Rejects guardrail fields on a service app and CIDRs Node's parser refuses. */
function assertAgentFields(kind: "service" | "agent", input: AgentFieldsInput): void {
  if (kind !== "agent" && hasAgentField(input)) {
    throw new ApiError(
      400,
      "agent_fields_on_service",
      "Agent fields are only allowed on agent applications",
    );
  }
  try {
    parseCidrs(input.allowedCidrs ?? []);
  } catch {
    throw new ApiError(400, "invalid_cidr", "allowedCidrs contains an invalid CIDR");
  }
}

const noKey = () =>
  new ApiError(
    409,
    "no_application_key",
    "Register an active public key before switching to private_key_jwt",
  );

/** private_key_jwt without an active registered key would lock the client out. */
async function assertHasActiveKey(tenantId: string, appId: string): Promise<void> {
  const [key] = await db
    .select({ id: applicationKeys.id })
    .from(applicationKeys)
    .where(
      and(
        eq(applicationKeys.tenantId, tenantId),
        eq(applicationKeys.applicationId, appId),
        eq(applicationKeys.status, "active"),
      ),
    )
    .limit(1);
  if (!key) throw noKey();
}

const notFound = () => new ApiError(404, "application_not_found", "Application not found");

/** Maps the `(tenant_id, name)` unique violation to 409; rethrows anything else. */
function mapNameConflict(err: unknown): never {
  const cause = (err as { cause?: { code?: string; constraint?: string } }).cause;
  if (cause?.code === "23505" && cause.constraint === "uq_applications_tenant_id_name") {
    throw new ApiError(409, "application_exists", "An application with this name already exists");
  }
  throw err;
}

export async function createApplication(
  tenantId: string,
  input: ApplicationCreateInput,
  createdBy?: string,
): Promise<{ application: ApplicationDto; clientSecret: string }> {
  const kind = input.kind ?? "service";
  assertAgentFields(kind, input);
  // A new application has no keys yet: private_key_jwt is reachable only via PATCH after registering one.
  if (input.tokenEndpointAuthMethod === "private_key_jwt") throw noKey();
  const clientSecret = generateClientSecret();
  const clientSecretHash = await hashSecret(clientSecret);
  const [row] = await db
    .insert(applications)
    .values({
      tenantId,
      name: input.name,
      description: input.description ?? null,
      kind,
      clientId: generateClientId(),
      clientSecretHash,
      tokenEndpointAuthMethod: input.tokenEndpointAuthMethod ?? "client_secret_basic",
      tokenTtlSeconds: input.tokenTtlSeconds ?? null,
      createdBy: createdBy ?? null,
      agentRuntime: input.agentRuntime ?? null,
      operatorEmail: input.operatorEmail ?? null,
      allowedCidrs: input.allowedCidrs ?? [],
      maxScopesPerToken: input.maxScopesPerToken ?? null,
      tokenBudgetPerHour: input.tokenBudgetPerHour ?? null,
      mayActFor: input.mayActFor ?? [],
      delegationScopeMode: input.delegationScopeMode ?? "intersection",
    })
    .returning()
    .catch(mapNameConflict);
  return { application: toApplicationDto(row), clientSecret };
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

export async function listApplications(
  tenantId: string,
  filters: { q?: string; status?: ApplicationListStatus; kind?: "service" | "agent" } = {},
): Promise<ApplicationListItem[]> {
  // Per-application grant summary, computed once for the tenant and joined (no N+1).
  const grantSummary = db
    .select({
      applicationId: applicationGrants.applicationId,
      resourceCount: sql<number>`count(distinct ${scopes.resourceId})::int`.as("resource_count"),
      scopeNames: sql<string[]>`array_agg(distinct ${scopes.name} order by ${scopes.name})`.as(
        "scope_names",
      ),
    })
    .from(applicationGrants)
    .innerJoin(
      scopes,
      and(
        eq(scopes.tenantId, applicationGrants.tenantId),
        eq(scopes.id, applicationGrants.scopeId),
      ),
    )
    .where(eq(applicationGrants.tenantId, tenantId))
    .groupBy(applicationGrants.applicationId)
    .as("grant_summary");

  const conditions: SQL[] = [eq(applications.tenantId, tenantId)];
  if (filters.q) {
    const pattern = `%${escapeLike(filters.q)}%`;
    conditions.push(
      or(ilike(applications.name, pattern), ilike(applications.clientId, pattern)) as SQL,
    );
  }
  if (filters.kind) conditions.push(eq(applications.kind, filters.kind));
  if (filters.status === "active" || filters.status === "disabled") {
    conditions.push(eq(applications.status, filters.status));
  } else if (filters.status === "needs_attention") {
    conditions.push(
      or(
        eq(applications.status, "disabled"),
        gt(applications.previousSecretExpiresAt, sql`now()`),
      ) as SQL,
    );
  }

  const rows = await db
    .select({
      app: applications,
      resourceCount: grantSummary.resourceCount,
      scopeNames: grantSummary.scopeNames,
    })
    .from(applications)
    .leftJoin(grantSummary, eq(grantSummary.applicationId, applications.id))
    .where(and(...conditions))
    .orderBy(asc(applications.name));

  return rows.map((r) => ({
    ...toApplicationDto(r.app),
    resourceCount: r.resourceCount ?? 0,
    scopeNames: r.scopeNames ?? [],
  }));
}

export async function getApplication(tenantId: string, appId: string): Promise<ApplicationDto> {
  const [row] = await db
    .select()
    .from(applications)
    .where(and(eq(applications.tenantId, tenantId), eq(applications.id, appId)))
    .limit(1);
  if (!row) throw notFound();
  return toApplicationDto(row);
}

async function updateOne(
  tenantId: string,
  appId: string,
  set: Partial<typeof applications.$inferInsert>,
): Promise<ApplicationDto> {
  const [row] = await db
    .update(applications)
    .set(set)
    .where(and(eq(applications.tenantId, tenantId), eq(applications.id, appId)))
    .returning()
    .catch(mapNameConflict);
  if (!row) throw notFound();
  return toApplicationDto(row);
}

export async function updateApplication(
  tenantId: string,
  appId: string,
  input: ApplicationUpdateInput,
): Promise<ApplicationDto> {
  // Only guarded patches pay for the extra read; the common path stays one statement.
  if (hasAgentField(input) || input.tokenEndpointAuthMethod === "private_key_jwt") {
    const current = await getApplication(tenantId, appId);
    assertAgentFields(current.kind, input);
    if (
      input.tokenEndpointAuthMethod === "private_key_jwt" &&
      current.tokenEndpointAuthMethod !== "private_key_jwt"
    ) {
      await assertHasActiveKey(tenantId, appId);
    }
  }
  const set = {
    name: input.name,
    description: input.description,
    tokenEndpointAuthMethod: input.tokenEndpointAuthMethod,
    tokenTtlSeconds: input.tokenTtlSeconds,
    agentRuntime: input.agentRuntime,
    operatorEmail: input.operatorEmail,
    allowedCidrs: input.allowedCidrs === null ? [] : input.allowedCidrs,
    maxScopesPerToken: input.maxScopesPerToken,
    tokenBudgetPerHour: input.tokenBudgetPerHour,
    mayActFor: input.mayActFor,
    delegationScopeMode: input.delegationScopeMode,
  };
  // Drizzle rejects an empty SET; an empty PATCH is a no-op read.
  if (Object.values(set).every((v) => v === undefined)) return getApplication(tenantId, appId);
  return updateOne(tenantId, appId, set);
}

export async function deleteApplication(tenantId: string, appId: string): Promise<void> {
  const deleted = await db
    .delete(applications)
    .where(and(eq(applications.tenantId, tenantId), eq(applications.id, appId)))
    .returning({ id: applications.id });
  if (deleted.length === 0) throw notFound();
}

export async function setApplicationStatus(
  tenantId: string,
  appId: string,
  status: "active" | "disabled",
): Promise<ApplicationDto> {
  return updateOne(tenantId, appId, { status });
}

/**
 * Issues a new secret; the old one keeps working until `now + graceSeconds`.
 * `graceSeconds = 0` invalidates the old secret immediately.
 */
export async function rotateSecret(
  tenantId: string,
  appId: string,
  graceSeconds: number,
): Promise<{ clientSecret: string; previousSecretExpiresAt: string | null }> {
  const clientSecret = generateClientSecret();
  const clientSecretHash = await hashSecret(clientSecret);
  const now = new Date();
  const previousSecretExpiresAt =
    graceSeconds > 0 ? new Date(now.getTime() + graceSeconds * 1000) : null;

  const [row] = await db
    .update(applications)
    .set({
      // RHS column refs read the pre-update value, so the shift is atomic in one statement.
      previousSecretHash: previousSecretExpiresAt ? sql`${applications.clientSecretHash}` : null,
      previousSecretExpiresAt,
      secretRotatedAt: now,
      clientSecretHash,
    })
    .where(and(eq(applications.tenantId, tenantId), eq(applications.id, appId)))
    .returning({ id: applications.id });
  if (!row) throw notFound();

  return { clientSecret, previousSecretExpiresAt: iso(previousSecretExpiresAt) };
}

/** Tokens of this application with `iat < tokens_not_before` become inactive (enforced by introspection). */
export async function revokeAllApplicationTokens(
  tenantId: string,
  appId: string,
): Promise<ApplicationDto> {
  return updateOne(tenantId, appId, { tokensNotBefore: new Date() });
}
