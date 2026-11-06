import { db, tenants } from "@handsal/db";
import { eq } from "drizzle-orm";

export type Tenant = typeof tenants.$inferSelect;

export async function getTenantBySlug(slug: string): Promise<Tenant | null> {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.slug, slug)).limit(1);
  return tenant ?? null;
}

export async function getTenantById(id: string): Promise<Tenant | null> {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.id, id)).limit(1);
  return tenant ?? null;
}
