import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { db, pool } from "./client.js";
import { runMigrations } from "./migrate.js";
import {
  adminUsers,
  applicationGrants,
  applications,
  resources,
  revokedTokens,
  scopes,
  signingKeys,
  tenantMembers,
  tenants,
  tokenEvents,
} from "./schema/index.js";

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

// Drizzle wraps driver errors; the pg SQLSTATE lives on the cause.
async function pgErrorCode(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (err: any) {
    return err?.cause?.code ?? err?.code;
  }
  return undefined;
}

async function createTenant(slug: string) {
  const [tenant] = await db.insert(tenants).values({ name: slug, slug }).returning();
  return tenant;
}

async function createResource(tenantId: string, name = "API") {
  const [resource] = await db
    .insert(resources)
    .values({ tenantId, name, audience: `https://${name.toLowerCase()}.example` })
    .returning();
  return resource;
}

function signingKey(tenantId: string, kid: string) {
  return { tenantId, kid, publicKeyPem: "pub", privateKeyEnc: "enc" };
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await db.execute(sql.raw(`TRUNCATE TABLE ${TABLES.join(", ")} RESTART IDENTITY CASCADE`));
});

afterAll(async () => {
  await pool.end();
});

describe("schema constraints", () => {
  it("rejects a scope whose resource belongs to another tenant", async () => {
    const a = await createTenant("tenant-a");
    const b = await createTenant("tenant-b");
    const resourceOfB = await createResource(b.id);

    const code = await pgErrorCode(
      db.insert(scopes).values({ tenantId: a.id, resourceId: resourceOfB.id, name: "x:read" }),
    );

    expect(code).toBe("23503"); // foreign_key_violation
  });

  it("rejects a grant linking an application and a scope of different tenants", async () => {
    const a = await createTenant("tenant-a");
    const b = await createTenant("tenant-b");
    const [appOfA] = await db
      .insert(applications)
      .values({ tenantId: a.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();
    const resourceOfB = await createResource(b.id);
    const [scopeOfB] = await db
      .insert(scopes)
      .values({ tenantId: b.id, resourceId: resourceOfB.id, name: "x:read" })
      .returning();

    const code = await pgErrorCode(
      db
        .insert(applicationGrants)
        .values({ tenantId: a.id, applicationId: appOfA.id, scopeId: scopeOfB.id }),
    );

    expect(code).toBe("23503");
  });

  it("allows only one active signing key per tenant", async () => {
    const tenant = await createTenant("tenant-a");
    const other = await createTenant("tenant-b");
    await db.insert(signingKeys).values(signingKey(tenant.id, "k_1"));
    await db.insert(signingKeys).values({ ...signingKey(tenant.id, "k_2"), status: "retiring" });
    await db.insert(signingKeys).values(signingKey(other.id, "k_3"));

    const code = await pgErrorCode(db.insert(signingKeys).values(signingKey(tenant.id, "k_4")));

    expect(code).toBe("23505"); // unique_violation
  });

  it("cascades a tenant delete to every child table", async () => {
    const tenant = await createTenant("tenant-a");
    const [admin] = await db
      .insert(adminUsers)
      .values({ email: "a@example.com", passwordHash: "h", name: "A" })
      .returning();
    await db
      .insert(tenantMembers)
      .values({ tenantId: tenant.id, adminUserId: admin.id, role: "owner" });
    const [app] = await db
      .insert(applications)
      .values({ tenantId: tenant.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();
    const resource = await createResource(tenant.id);
    const [scope] = await db
      .insert(scopes)
      .values({ tenantId: tenant.id, resourceId: resource.id, name: "x:read" })
      .returning();
    await db
      .insert(applicationGrants)
      .values({ tenantId: tenant.id, applicationId: app.id, scopeId: scope.id });
    await db.insert(signingKeys).values(signingKey(tenant.id, "k_1"));
    await db
      .insert(revokedTokens)
      .values({ jti: "jti-1", tenantId: tenant.id, expiresAt: new Date(Date.now() + 60_000) });
    await db.insert(tokenEvents).values({
      tenantId: tenant.id,
      applicationId: app.id,
      outcome: "issued",
      scopes: ["x:read"],
    });

    const children = TABLES.filter((t) => t !== "tenants" && t !== "admin_users");
    const count = async (table: string) => {
      const { rows } = await pool.query(`SELECT count(*)::int AS n FROM ${table}`);
      return rows[0].n as number;
    };
    for (const table of children) expect(await count(table), table).toBe(1);

    await db.delete(tenants).where(eq(tenants.id, tenant.id));

    for (const table of children) expect(await count(table), table).toBe(0);
    expect(await count("admin_users")).toBe(1);
  });
});
