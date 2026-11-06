import { randomBytes } from "node:crypto";
import { db, tenants } from "@handsal/db";
import { sql } from "drizzle-orm";

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

/** Empty every table (integration tests call this in `beforeEach`). */
export async function truncateAll(): Promise<void> {
  await db.execute(sql.raw(`TRUNCATE TABLE ${TABLES.join(", ")} RESTART IDENTITY CASCADE`));
}

export async function createTenant(over: Partial<typeof tenants.$inferInsert> = {}) {
  const slug = `t-${randomBytes(4).toString("hex")}`;
  const [tenant] = await db
    .insert(tenants)
    .values({ name: slug, slug, ...over })
    .returning();
  return tenant;
}
