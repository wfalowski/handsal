import { applicationGrants, applications, db, resources, scopes, tokenEvents } from "@handsal/db";
import type {
  ResourceDto,
  resourceCreateSchema,
  resourceUpdateSchema,
  ScopeDto,
} from "@handsal/shared";
import { and, asc, eq, sql } from "drizzle-orm";
import { z } from "zod";
import { ApiError } from "../middleware/error-handler.js";

type ResourceRow = typeof resources.$inferSelect;
type ScopeRow = typeof scopes.$inferSelect;
export type ResourceCreateInput = z.infer<typeof resourceCreateSchema>;
export type ResourceUpdateInput = z.infer<typeof resourceUpdateSchema>;
export type ResourceListItem = ResourceDto & {
  scopeCount: number;
  appCount: number;
  tokens24h: number;
};
export type ResourceDetail = ResourceDto & {
  scopes: (ScopeDto & { grantedAppCount: number })[];
  applications: { id: string; name: string; clientId: string }[];
};

export function toResourceDto(row: ResourceRow): ResourceDto {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    audience: row.audience,
    tokenTtlSeconds: row.tokenTtlSeconds,
    status: row.status,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** Lives here (not in scope.service) so the dependency stays one-way: scope → resource. */
export function toScopeDto(row: ScopeRow): ScopeDto {
  return {
    id: row.id,
    resourceId: row.resourceId,
    name: row.name,
    description: row.description,
    agentPolicy: row.agentPolicy,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const notFound = () => new ApiError(404, "resource_not_found", "Resource not found");

/** Non-UUID ids would make Postgres throw (500); treat them as unknown instead. */
export function assertUuid(id: string, notFoundError: () => ApiError): void {
  if (!z.uuid().safeParse(id).success) throw notFoundError();
}

/** Maps the `(tenant_id, audience)` / `(tenant_id, name)` unique violations to 409. */
function mapConflict(err: unknown): never {
  const cause = (err as { cause?: { code?: string; constraint?: string } }).cause;
  if (cause?.code === "23505") {
    if (cause.constraint === "uq_resources_tenant_id_audience") {
      throw new ApiError(409, "audience_exists", "A resource with this audience already exists");
    }
    if (cause.constraint === "uq_resources_tenant_id_name") {
      throw new ApiError(409, "resource_name_exists", "A resource with this name already exists");
    }
  }
  throw err;
}

async function getResourceRow(tenantId: string, resourceId: string): Promise<ResourceRow> {
  assertUuid(resourceId, notFound);
  const [row] = await db
    .select()
    .from(resources)
    .where(and(eq(resources.tenantId, tenantId), eq(resources.id, resourceId)))
    .limit(1);
  if (!row) throw notFound();
  return row;
}

export async function createResource(
  tenantId: string,
  input: ResourceCreateInput,
): Promise<ResourceDto> {
  const [row] = await db
    .insert(resources)
    .values({
      tenantId,
      name: input.name,
      kind: input.kind ?? "api",
      audience: input.audience,
      tokenTtlSeconds: input.tokenTtlSeconds ?? null,
    })
    .returning()
    .catch(mapConflict);
  return toResourceDto(row);
}

export async function listResources(tenantId: string): Promise<ResourceListItem[]> {
  const scopeStats = db
    .select({
      resourceId: scopes.resourceId,
      scopeCount: sql<number>`count(distinct ${scopes.id})::int`.as("scope_count"),
      appCount: sql<number>`count(distinct ${applicationGrants.applicationId})::int`.as(
        "app_count",
      ),
    })
    .from(scopes)
    .leftJoin(
      applicationGrants,
      and(
        eq(applicationGrants.tenantId, scopes.tenantId),
        eq(applicationGrants.scopeId, scopes.id),
      ),
    )
    .where(eq(scopes.tenantId, tenantId))
    .groupBy(scopes.resourceId)
    .as("scope_stats");

  const tokenStats = db
    .select({
      resourceId: tokenEvents.resourceId,
      tokens24h: sql<number>`count(*)::int`.as("tokens_24h"),
    })
    .from(tokenEvents)
    .where(
      and(
        eq(tokenEvents.tenantId, tenantId),
        eq(tokenEvents.outcome, "issued"),
        sql`${tokenEvents.createdAt} > now() - interval '24 hours'`,
      ),
    )
    .groupBy(tokenEvents.resourceId)
    .as("token_stats");

  const rows = await db
    .select({
      resource: resources,
      scopeCount: scopeStats.scopeCount,
      appCount: scopeStats.appCount,
      tokens24h: tokenStats.tokens24h,
    })
    .from(resources)
    .leftJoin(scopeStats, eq(scopeStats.resourceId, resources.id))
    .leftJoin(tokenStats, eq(tokenStats.resourceId, resources.id))
    .where(eq(resources.tenantId, tenantId))
    .orderBy(asc(resources.name));

  return rows.map((r) => ({
    ...toResourceDto(r.resource),
    scopeCount: r.scopeCount ?? 0,
    appCount: r.appCount ?? 0,
    tokens24h: r.tokens24h ?? 0,
  }));
}

export async function getResourceDetail(
  tenantId: string,
  resourceId: string,
): Promise<ResourceDetail> {
  const resource = await getResourceRow(tenantId, resourceId);
  const grantJoin = and(
    eq(applicationGrants.tenantId, scopes.tenantId),
    eq(applicationGrants.scopeId, scopes.id),
  );
  const ofResource = and(eq(scopes.tenantId, tenantId), eq(scopes.resourceId, resourceId));

  const [scopeRows, appRows] = await Promise.all([
    db
      .select({
        scope: scopes,
        grantedAppCount: sql<number>`count(${applicationGrants.applicationId})::int`,
      })
      .from(scopes)
      .leftJoin(applicationGrants, grantJoin)
      .where(ofResource)
      .groupBy(scopes.id)
      .orderBy(asc(scopes.name)),
    db
      .selectDistinct({
        id: applications.id,
        name: applications.name,
        clientId: applications.clientId,
      })
      .from(scopes)
      .innerJoin(applicationGrants, grantJoin)
      .innerJoin(
        applications,
        and(
          eq(applications.tenantId, applicationGrants.tenantId),
          eq(applications.id, applicationGrants.applicationId),
        ),
      )
      .where(ofResource)
      .orderBy(asc(applications.name), asc(applications.id)),
  ]);

  return {
    ...toResourceDto(resource),
    scopes: scopeRows.map((r) => ({ ...toScopeDto(r.scope), grantedAppCount: r.grantedAppCount })),
    applications: appRows,
  };
}

export async function updateResource(
  tenantId: string,
  resourceId: string,
  input: ResourceUpdateInput,
): Promise<ResourceDto> {
  const set = {
    name: input.name,
    kind: input.kind,
    audience: input.audience,
    tokenTtlSeconds: input.tokenTtlSeconds,
  };
  // Drizzle rejects an empty SET; an empty PATCH is a no-op read.
  if (Object.values(set).every((v) => v === undefined)) {
    return toResourceDto(await getResourceRow(tenantId, resourceId));
  }
  assertUuid(resourceId, notFound);
  const [row] = await db
    .update(resources)
    .set(set)
    .where(and(eq(resources.tenantId, tenantId), eq(resources.id, resourceId)))
    .returning()
    .catch(mapConflict);
  if (!row) throw notFound();
  return toResourceDto(row);
}

/** Scopes and their grants go with it (FK `on delete cascade`). */
export async function deleteResource(tenantId: string, resourceId: string): Promise<void> {
  assertUuid(resourceId, notFound);
  const deleted = await db
    .delete(resources)
    .where(and(eq(resources.tenantId, tenantId), eq(resources.id, resourceId)))
    .returning({ id: resources.id });
  if (deleted.length === 0) throw notFound();
}

/** Throws 404 `resource_not_found` unless the resource exists in the tenant. */
export async function assertResource(tenantId: string, resourceId: string): Promise<void> {
  await getResourceRow(tenantId, resourceId);
}
