import { randomUUID } from "node:crypto";
import { applicationGrants, db, resources, scopes, tenants } from "@handsal/db";
import { sql } from "drizzle-orm";
import {
  type ApplicationCreateInput,
  createApplication as createApplicationService,
} from "../services/application.service.js";

const TABLES = [
  "token_events",
  "revoked_tokens",
  "signing_keys",
  "application_grants",
  "scopes",
  "resources",
  "applications",
  "tenant_members",
  "admin_users",
  "tenants",
];

export async function truncateAll(): Promise<void> {
  await db.execute(sql.raw(`TRUNCATE TABLE ${TABLES.join(", ")} RESTART IDENTITY CASCADE`));
}

const uniq = () => randomUUID().slice(0, 8);

export async function createTenant(over: Partial<typeof tenants.$inferInsert> = {}) {
  const slug = over.slug ?? `tenant-${uniq()}`;
  const [tenant] = await db
    .insert(tenants)
    .values({ name: slug, slug, ...over })
    .returning();
  return tenant;
}

export async function createApplication(
  tenantId: string,
  over: Partial<ApplicationCreateInput> = {},
) {
  return createApplicationService(tenantId, { name: `app-${uniq()}`, ...over });
}

export async function createResourceWithScopes(
  tenantId: string,
  audience: string,
  scopeNames: string[],
  over: Partial<typeof resources.$inferInsert> = {},
) {
  const [resource] = await db
    .insert(resources)
    .values({ tenantId, name: `resource-${uniq()}`, audience, ...over })
    .returning();
  const created =
    scopeNames.length === 0
      ? []
      : await db
          .insert(scopes)
          .values(scopeNames.map((name) => ({ tenantId, resourceId: resource.id, name })))
          .returning();
  return { resource, scopes: created };
}

export async function grant(tenantId: string, appId: string, scopeIds: string[]): Promise<void> {
  await db
    .insert(applicationGrants)
    .values(scopeIds.map((scopeId) => ({ tenantId, applicationId: appId, scopeId })));
}
