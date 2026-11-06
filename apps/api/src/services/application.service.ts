import { applicationGrants, applications, db, scopes } from "@handsal/db";
import type {
  ApplicationDto,
  applicationCreateSchema,
  applicationUpdateSchema,
} from "@handsal/shared";
import { and, asc, eq, gt, ilike, or, type SQL, sql } from "drizzle-orm";
import type { z } from "zod";
import { ApiError } from "../middleware/error-handler.js";
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
  };
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
  const clientSecret = generateClientSecret();
  const clientSecretHash = await hashSecret(clientSecret);
  const [row] = await db
    .insert(applications)
    .values({
      tenantId,
      name: input.name,
      description: input.description ?? null,
      kind: "service",
      clientId: generateClientId(),
      clientSecretHash,
      tokenEndpointAuthMethod: input.tokenEndpointAuthMethod ?? "client_secret_basic",
      tokenTtlSeconds: input.tokenTtlSeconds ?? null,
      createdBy: createdBy ?? null,
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
  filters: { q?: string; status?: ApplicationListStatus } = {},
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
  return updateOne(tenantId, appId, {
    name: input.name,
    description: input.description,
    tokenEndpointAuthMethod: input.tokenEndpointAuthMethod,
    tokenTtlSeconds: input.tokenTtlSeconds,
  });
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
