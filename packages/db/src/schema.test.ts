import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { db, pool } from "./client.js";
import { runMigrations } from "./migrate.js";
import {
  adminUsers,
  applicationGrants,
  applicationKeys,
  applications,
  approvalRequests,
  approvalRules,
  resources,
  revokedTokens,
  scopes,
  signingKeys,
  tenantMembers,
  tenants,
  tokenEvents,
} from "./schema/index.js";

const TABLES = [
  "approval_requests",
  "approval_rules",
  "token_events",
  "revoked_tokens",
  "signing_keys",
  "application_keys",
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

function applicationKey(tenantId: string, applicationId: string, kid: string) {
  return { tenantId, applicationId, kid, publicKeyPem: "pub", fingerprintSha256: `fp-${kid}` };
}

function approvalRequest(
  tenantId: string,
  applicationId: string,
  resourceId: string,
  audience: string,
) {
  const expiresAt = new Date(Date.now() + 30 * 60_000);
  return { tenantId, applicationId, resourceId, audience, scopes: ["x:read"], expiresAt };
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

  it("rejects an application key whose application belongs to another tenant", async () => {
    const a = await createTenant("tenant-a");
    const b = await createTenant("tenant-b");
    const [appOfB] = await db
      .insert(applications)
      .values({ tenantId: b.id, name: "app", clientId: "app_bbbbbbbbbbbbbbbbbbbb" })
      .returning();

    const code = await pgErrorCode(
      db.insert(applicationKeys).values(applicationKey(a.id, appOfB.id, "ak_1")),
    );

    expect(code).toBe("23503");
  });

  it("rejects a duplicate kid or fingerprint within one application", async () => {
    const tenant = await createTenant("tenant-a");
    const [app] = await db
      .insert(applications)
      .values({ tenantId: tenant.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();
    await db.insert(applicationKeys).values(applicationKey(tenant.id, app.id, "ak_1"));

    const dupKid = { ...applicationKey(tenant.id, app.id, "ak_1"), fingerprintSha256: "other" };
    const dupFingerprint = {
      ...applicationKey(tenant.id, app.id, "ak_2"),
      fingerprintSha256: "fp-ak_1",
    };
    expect(await pgErrorCode(db.insert(applicationKeys).values(dupKid))).toBe("23505");
    expect(await pgErrorCode(db.insert(applicationKeys).values(dupFingerprint))).toBe("23505");
  });

  it("cascades an application delete to its keys", async () => {
    const tenant = await createTenant("tenant-a");
    const [app] = await db
      .insert(applications)
      .values({ tenantId: tenant.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();
    await db.insert(applicationKeys).values(applicationKey(tenant.id, app.id, "ak_1"));

    await db.delete(applications).where(eq(applications.id, app.id));

    expect(await db.select().from(applicationKeys)).toHaveLength(0);
  });

  it("rejects an approval request whose application or resource belongs to another tenant", async () => {
    const a = await createTenant("tenant-a");
    const b = await createTenant("tenant-b");
    const [appOfA] = await db
      .insert(applications)
      .values({ tenantId: a.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();
    const [appOfB] = await db
      .insert(applications)
      .values({ tenantId: b.id, name: "app", clientId: "app_bbbbbbbbbbbbbbbbbbbb" })
      .returning();
    const resourceOfA = await createResource(a.id);
    const resourceOfB = await createResource(b.id);

    expect(
      await pgErrorCode(
        db
          .insert(approvalRequests)
          .values(approvalRequest(a.id, appOfB.id, resourceOfA.id, resourceOfA.audience)),
      ),
    ).toBe("23503");
    expect(
      await pgErrorCode(
        db
          .insert(approvalRequests)
          .values(approvalRequest(a.id, appOfA.id, resourceOfB.id, resourceOfB.audience)),
      ),
    ).toBe("23503");
  });

  it("cascades application and resource deletes to approval requests and nulls decided_by", async () => {
    const tenant = await createTenant("tenant-a");
    const [admin] = await db
      .insert(adminUsers)
      .values({ email: "a@example.com", passwordHash: "h", name: "A" })
      .returning();
    const [app] = await db
      .insert(applications)
      .values({ tenantId: tenant.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();
    const resource = await createResource(tenant.id);
    const other = await createResource(tenant.id, "Other");
    const [decided] = await db
      .insert(approvalRequests)
      .values({
        ...approvalRequest(tenant.id, app.id, resource.id, resource.audience),
        status: "approved",
        decidedBy: admin.id,
        decidedAt: new Date(),
      })
      .returning();
    expect(decided.scopes).toEqual(["x:read"]);
    await db
      .insert(approvalRequests)
      .values(approvalRequest(tenant.id, app.id, other.id, other.audience));

    await db.delete(adminUsers).where(eq(adminUsers.id, admin.id));
    const [row] = await db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.id, decided.id));
    expect(row.decidedBy).toBeNull();

    await db.delete(resources).where(eq(resources.id, other.id));
    expect(await db.select().from(approvalRequests)).toHaveLength(1);
    await db.delete(applications).where(eq(applications.id, app.id));
    expect(await db.select().from(approvalRequests)).toHaveLength(0);
  });

  it("rejects an approval rule whose scope belongs to another tenant", async () => {
    const a = await createTenant("tenant-a");
    const b = await createTenant("tenant-b");
    const resourceOfB = await createResource(b.id);
    const [scopeOfB] = await db
      .insert(scopes)
      .values({ tenantId: b.id, resourceId: resourceOfB.id, name: "x:write" })
      .returning();

    const code = await pgErrorCode(
      db.insert(approvalRules).values({ tenantId: a.id, scopeId: scopeOfB.id }),
    );

    expect(code).toBe("23503");
  });

  it("cascades scope deletes to approval rules and nulls decided_by_rule_id", async () => {
    const tenant = await createTenant("tenant-a");
    const [app] = await db
      .insert(applications)
      .values({ tenantId: tenant.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();
    const resource = await createResource(tenant.id);
    const [scope] = await db
      .insert(scopes)
      .values({ tenantId: tenant.id, resourceId: resource.id, name: "x:write" })
      .returning();
    const [rule] = await db
      .insert(approvalRules)
      .values({ tenantId: tenant.id, scopeId: scope.id, condition: { max_scopes: 2 } })
      .returning();
    expect(rule.condition).toEqual({ max_scopes: 2 });
    expect(rule.action).toBe("auto_approve");
    const [decided] = await db
      .insert(approvalRequests)
      .values({
        ...approvalRequest(tenant.id, app.id, resource.id, resource.audience),
        status: "approved",
        decidedByRuleId: rule.id,
        decidedAt: new Date(),
      })
      .returning();

    await db.delete(scopes).where(eq(scopes.id, scope.id));

    expect(await db.select().from(approvalRules)).toHaveLength(0);
    const [row] = await db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.id, decided.id));
    expect(row.decidedByRuleId).toBeNull();
    expect(row.status).toBe("approved");
  });

  it("defaults token-exchange delegation settings and stores external_idp", async () => {
    const idp = {
      issuer: "https://idp.example",
      jwksUri: "https://idp.example/jwks",
      audience: "a",
    };
    const [tenant] = await db
      .insert(tenants)
      .values({ name: "t", slug: "tenant-a", externalIdp: idp })
      .returning();
    const [app] = await db
      .insert(applications)
      .values({ tenantId: tenant.id, name: "app", clientId: "app_aaaaaaaaaaaaaaaaaaaa" })
      .returning();

    expect(tenant.externalIdp).toEqual(idp);
    expect(app.mayActFor).toEqual([]);
    expect(app.delegationScopeMode).toBe("intersection");
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
    await db.insert(applicationKeys).values(applicationKey(tenant.id, app.id, "ak_1"));
    await db
      .insert(revokedTokens)
      .values({ jti: "jti-1", tenantId: tenant.id, expiresAt: new Date(Date.now() + 60_000) });
    await db.insert(tokenEvents).values({
      tenantId: tenant.id,
      applicationId: app.id,
      outcome: "issued",
      scopes: ["x:read"],
    });
    await db
      .insert(approvalRequests)
      .values(approvalRequest(tenant.id, app.id, resource.id, resource.audience));
    await db.insert(approvalRules).values({ tenantId: tenant.id, scopeId: scope.id });

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
