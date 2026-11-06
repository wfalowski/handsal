import { applicationGrants, applications, db, resources, scopes } from "@handsal/db";
import { and, asc, eq, inArray } from "drizzle-orm";
import { ApiError } from "../middleware/error-handler.js";

type ResourceKind = (typeof resources.$inferSelect)["kind"];
type ResourceStatus = (typeof resources.$inferSelect)["status"];

export interface GrantView {
  resource: { id: string; name: string; audience: string; kind: ResourceKind };
  scopes: { id: string; name: string }[];
}

export interface GrantedResource {
  id: string;
  name: string;
  audience: string;
  kind: ResourceKind;
  status: ResourceStatus;
  tokenTtlSeconds: number | null;
}

const grantedScopeJoin = and(
  eq(scopes.tenantId, applicationGrants.tenantId),
  eq(scopes.id, applicationGrants.scopeId),
);
const scopeResourceJoin = and(
  eq(resources.tenantId, scopes.tenantId),
  eq(resources.id, scopes.resourceId),
);

/** Replaces the application's grant set atomically; every scope id must belong to the tenant. */
export async function replaceGrants(
  tenantId: string,
  appId: string,
  scopeIds: string[],
): Promise<GrantView[]> {
  const ids = [...new Set(scopeIds)];

  await db.transaction(async (tx) => {
    const [app] = await tx
      .select({ id: applications.id })
      .from(applications)
      .where(and(eq(applications.tenantId, tenantId), eq(applications.id, appId)))
      .limit(1);
    if (!app) throw new ApiError(404, "application_not_found", "Application not found");

    if (ids.length > 0) {
      const found = await tx
        .select({ id: scopes.id })
        .from(scopes)
        .where(and(eq(scopes.tenantId, tenantId), inArray(scopes.id, ids)));
      const known = new Set(found.map((s) => s.id));
      const unknown = ids.filter((id) => !known.has(id));
      if (unknown.length > 0) {
        throw new ApiError(400, "invalid_scope_ids", "Some scope ids do not exist in this tenant", {
          unknown,
        });
      }
    }

    await tx
      .delete(applicationGrants)
      .where(
        and(eq(applicationGrants.tenantId, tenantId), eq(applicationGrants.applicationId, appId)),
      );
    if (ids.length > 0) {
      await tx
        .insert(applicationGrants)
        .values(ids.map((scopeId) => ({ tenantId, applicationId: appId, scopeId })));
    }
  });

  return getGrants(tenantId, appId);
}

/** Grants grouped by resource, ordered by resource name then scope name. */
export async function getGrants(tenantId: string, appId: string): Promise<GrantView[]> {
  const rows = await db
    .select({
      resourceId: resources.id,
      resourceName: resources.name,
      audience: resources.audience,
      kind: resources.kind,
      scopeId: scopes.id,
      scopeName: scopes.name,
    })
    .from(applicationGrants)
    .innerJoin(scopes, grantedScopeJoin)
    .innerJoin(resources, scopeResourceJoin)
    .where(
      and(eq(applicationGrants.tenantId, tenantId), eq(applicationGrants.applicationId, appId)),
    )
    .orderBy(asc(resources.name), asc(scopes.name));

  const byResource = new Map<string, GrantView>();
  for (const r of rows) {
    let view = byResource.get(r.resourceId);
    if (!view) {
      view = {
        resource: { id: r.resourceId, name: r.resourceName, audience: r.audience, kind: r.kind },
        scopes: [],
      };
      byResource.set(r.resourceId, view);
    }
    view.scopes.push({ id: r.scopeId, name: r.scopeName });
  }
  return [...byResource.values()];
}

/**
 * The tenant resource with this audience plus the app's granted scope names on it, or null
 * when the audience is unknown in this tenant or the app has no grant on it.
 * Scope names are ordered by name (`application_grants` has no insertion timestamp).
 */
export async function getGrantedScopesForAudience(
  tenantId: string,
  appId: string,
  audience: string,
): Promise<{ resource: GrantedResource; scopeNames: string[] } | null> {
  const rows = await db
    .select({
      id: resources.id,
      name: resources.name,
      audience: resources.audience,
      kind: resources.kind,
      status: resources.status,
      tokenTtlSeconds: resources.tokenTtlSeconds,
      scopeName: scopes.name,
    })
    .from(applicationGrants)
    .innerJoin(scopes, grantedScopeJoin)
    .innerJoin(resources, scopeResourceJoin)
    .where(
      and(
        eq(applicationGrants.tenantId, tenantId),
        eq(applicationGrants.applicationId, appId),
        eq(resources.audience, audience),
      ),
    )
    .orderBy(asc(scopes.name));

  if (rows.length === 0) return null;
  const { scopeName: _, ...resource } = rows[0];
  return { resource, scopeNames: rows.map((r) => r.scopeName) };
}
