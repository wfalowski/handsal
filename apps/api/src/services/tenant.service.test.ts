import {
  applications,
  db,
  pool,
  resources,
  runMigrations,
  scopes,
  signingKeys,
  tenantMembers,
  tenants,
  tokenEvents,
} from "@handsal/db";
import { count, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, onTestFinished } from "vitest";
import { env } from "../env.js";
import { ApiError } from "../middleware/error-handler.js";
import {
  addMember,
  createAdminUser,
  createApplication,
  createResourceWithScopes,
  createTenant as createTenantRow,
  truncateAll,
} from "../test/factories.js";
import {
  createTenant,
  deleteTenant,
  getTenantDetail,
  listTenantsWithStats,
  revokeAllTenantTokens,
  setTenantStatus,
  toTenantDto,
  updateTenant,
} from "./tenant.service.js";
import { recordTokenEvent } from "./token-event.service.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

async function apiErrorOf(promise: Promise<unknown>): Promise<ApiError> {
  const err = await promise.then(
    () => {
      throw new Error("expected rejection");
    },
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ApiError);
  return err as ApiError;
}

const countWhere = async (
  table: typeof applications | typeof resources | typeof scopes | typeof signingKeys,
  tenantId: string,
) => (await db.select({ n: count() }).from(table).where(eq(table.tenantId, tenantId)))[0].n;

describe("createTenant", () => {
  it("creates the tenant, exactly one active signing key and one owner membership", async () => {
    const { user } = await createAdminUser();
    const tenant = await createTenant({ name: "Acme", slug: "acme" }, user.id);

    expect(tenant).toMatchObject({
      name: "Acme",
      slug: "acme",
      status: "active",
      issuer: "https://test.example.com/t/acme",
    });
    const keys = await db.select().from(signingKeys).where(eq(signingKeys.tenantId, tenant.id));
    expect(keys.map((k) => k.status)).toEqual(["active"]);
    const members = await db
      .select()
      .from(tenantMembers)
      .where(eq(tenantMembers.tenantId, tenant.id));
    expect(members).toEqual([{ tenantId: tenant.id, adminUserId: user.id, role: "owner" }]);
  });

  it("without a creator (API key) adds no membership", async () => {
    const tenant = await createTenant({ name: "Acme", slug: "acme" });
    expect(await countWhere(signingKeys, tenant.id)).toBe(1);
    const [{ n }] = await db
      .select({ n: count() })
      .from(tenantMembers)
      .where(eq(tenantMembers.tenantId, tenant.id));
    expect(n).toBe(0);
  });

  it("duplicate slug → 409 slug_exists and nothing else is written", async () => {
    await createTenant({ name: "A", slug: "acme" });
    const err = await apiErrorOf(createTenant({ name: "B", slug: "acme" }));
    expect([err.statusCode, err.errorCode]).toEqual([409, "slug_exists"]);
    expect(await db.select().from(tenants)).toHaveLength(1);
    expect(await db.select().from(signingKeys)).toHaveLength(1);
  });
});

describe("listTenantsWithStats", () => {
  it("returns counters per tenant and limits to memberships when a user is given", async () => {
    const { user } = await createAdminUser();
    const a = await createTenantRow({ name: "A" });
    const b = await createTenantRow({ name: "B" });
    await addMember(a.id, user.id, "auditor");
    await createApplication(a.id);
    await createApplication(a.id);
    await createResourceWithScopes(a.id, "https://api.a", ["read"]);
    await recordTokenEvent({ tenantId: a.id, outcome: "issued" });
    await recordTokenEvent({ tenantId: a.id, outcome: "denied" });
    await db
      .insert(tokenEvents)
      .values({ tenantId: a.id, outcome: "issued", createdAt: new Date(Date.now() - 25 * 3600e3) });

    const all = await listTenantsWithStats();
    expect(all.map((t) => [t.name, t.appCount, t.resourceCount, t.tokens24h, t.role])).toEqual([
      ["A", 2, 1, 1, "owner"],
      ["B", 0, 0, 0, "owner"],
    ]);

    const mine = await listTenantsWithStats(user.id);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ id: a.id, role: "auditor", appCount: 2 });
    expect(b.id).not.toBe(mine[0].id);
  });
});

describe("getTenantDetail / updates", () => {
  it("adds issuer URLs and stats", async () => {
    const t = await createTenantRow({ slug: "acme" });
    const detail = await getTenantDetail(t.id);
    expect(detail).toMatchObject({
      issuer: "https://test.example.com/t/acme",
      discoveryUrl: "https://test.example.com/t/acme/.well-known/openid-configuration",
      jwksUrl: "https://test.example.com/t/acme/.well-known/jwks.json",
      stats: { issued24h: 0, totalApps: 0 },
    });
  });

  it("update, pause/resume, revoke-all", async () => {
    const t = await createTenantRow();
    expect(
      await updateTenant(t.id, { name: "New", keyRotationDays: 30, introspectionEnabled: false }),
    ).toMatchObject({ name: "New", keyRotationDays: 30, introspectionEnabled: false });
    expect((await setTenantStatus(t.id, "paused")).status).toBe("paused");
    expect((await setTenantStatus(t.id, "active")).status).toBe("active");

    const before = Date.now();
    const revoked = await revokeAllTenantTokens(t.id);
    expect(new Date(revoked.tokensNotBefore as string).getTime()).toBeGreaterThanOrEqual(
      before - 1000,
    );
  });
});

describe("deleteTenant", () => {
  it("externalIdp defaults to null, sets and clears", async () => {
    const t = await createTenantRow();
    expect(toTenantDto(t).externalIdp).toBeNull();
    const idp = {
      issuer: "https://i.example.com",
      jwksUri: "https://i.example.com/j",
      audience: "a",
    };
    expect((await updateTenant(t.id, { externalIdp: idp })).externalIdp).toEqual(idp);
    expect((await updateTenant(t.id, { externalIdp: null })).externalIdp).toBeNull();
  });

  it("internal jwksUri / webhook destinations → 400 validation_error in production", async () => {
    const t = await createTenantRow();
    const idp = { issuer: "https://i.example.com", audience: "a" };
    const prev = env.NODE_ENV;
    env.NODE_ENV = "production";
    onTestFinished(() => {
      env.NODE_ENV = prev;
    });
    expect(
      (await updateTenant(t.id, { approvalWebhookUrl: "https://hooks.example.com/x" }))
        .approvalWebhookUrl,
    ).toBe("https://hooks.example.com/x");
    for (const input of [
      { externalIdp: { ...idp, jwksUri: "https://10.0.0.1/" } },
      { externalIdp: { ...idp, jwksUri: "https://[::1]/jwks" } },
      { externalIdp: { ...idp, jwksUri: "https://[::ffff:192.168.1.1]/jwks" } },
      { externalIdp: { ...idp, jwksUri: "https://169.254.169.254/latest" } },
      { externalIdp: { ...idp, jwksUri: "https://metadata.google.internal/" } },
      { approvalWebhookUrl: "http://localhost:8080/hook" },
      { approvalWebhookUrl: "https://printer.local/hook" },
      { approvalWebhookUrl: "https://[fd12::1]/hook" },
    ]) {
      const err = await apiErrorOf(updateTenant(t.id, input));
      expect([err.statusCode, err.errorCode]).toEqual([400, "validation_error"]);
    }
  });

  it("wrong confirmSlug → 400 confirm_slug_mismatch", async () => {
    const t = await createTenantRow({ slug: "acme" });
    const err = await apiErrorOf(deleteTenant(t.id, "acme2"));
    expect([err.statusCode, err.errorCode]).toEqual([400, "confirm_slug_mismatch"]);
  });

  it("cascades to every child table", async () => {
    const t = await createTenant({ name: "Acme", slug: "acme" });
    await createApplication(t.id);
    await createResourceWithScopes(t.id, "https://api.acme", ["read", "write"]);
    expect(await countWhere(applications, t.id)).toBe(1);
    expect(await countWhere(scopes, t.id)).toBe(2);
    expect(await countWhere(signingKeys, t.id)).toBe(1);

    await deleteTenant(t.id, "acme");
    for (const table of [applications, resources, scopes, signingKeys]) {
      expect(await countWhere(table, t.id)).toBe(0);
    }
  });
});
