import { applicationGrants, db, pool, runMigrations, scopes, tokenEvents } from "@handsal/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../middleware/error-handler.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.js";
import {
  createResource,
  deleteResource,
  getResourceDetail,
  listResources,
  updateResource,
} from "./resource.service.js";

async function apiErrorOf(promise: Promise<unknown>): Promise<ApiError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ApiError);
  return err as ApiError;
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

const PAYMENTS = "https://api.acme.io/payments";

describe("createResource", () => {
  it("creates with defaults", async () => {
    const tenant = await createTenant();
    const r = await createResource(tenant.id, { name: "Payments", audience: PAYMENTS });
    expect(r).toMatchObject({
      name: "Payments",
      kind: "api",
      audience: PAYMENTS,
      tokenTtlSeconds: null,
      status: "active",
    });
  });

  it("duplicate audience → 409 audience_exists; duplicate name → 409 resource_name_exists", async () => {
    const tenant = await createTenant();
    await createResource(tenant.id, { name: "Payments", audience: PAYMENTS });
    const a = await apiErrorOf(createResource(tenant.id, { name: "Other", audience: PAYMENTS }));
    expect([a.statusCode, a.errorCode]).toEqual([409, "audience_exists"]);
    const n = await apiErrorOf(
      createResource(tenant.id, { name: "Payments", audience: "urn:acme:other" }),
    );
    expect([n.statusCode, n.errorCode]).toEqual([409, "resource_name_exists"]);
  });

  it("same audience in another tenant is fine", async () => {
    const a = await createTenant();
    const b = await createTenant();
    await createResource(a.id, { name: "Payments", audience: PAYMENTS });
    await expect(
      createResource(b.id, { name: "Payments", audience: PAYMENTS }),
    ).resolves.toMatchObject({ audience: PAYMENTS });
  });
});

describe("listResources", () => {
  it("returns scopeCount, appCount (distinct apps) and tokens24h per resource", async () => {
    const tenant = await createTenant();
    const other = await createTenant();
    const pay = await createResourceWithScopes(tenant.id, PAYMENTS, ["p:read", "p:write"], {
      name: "A-payments",
    });
    await createResourceWithScopes(tenant.id, "urn:acme:empty", [], { name: "B-empty" });
    const app1 = (await createApplication(tenant.id)).application;
    const app2 = (await createApplication(tenant.id)).application;
    await grant(tenant.id, app1.id, [pay.scopes[0].id, pay.scopes[1].id]);
    await grant(tenant.id, app2.id, [pay.scopes[0].id]);

    const old = new Date(Date.now() - 25 * 3600 * 1000);
    await db.insert(tokenEvents).values([
      { tenantId: tenant.id, resourceId: pay.resource.id, outcome: "issued" },
      { tenantId: tenant.id, resourceId: pay.resource.id, outcome: "issued" },
      { tenantId: tenant.id, resourceId: pay.resource.id, outcome: "denied" },
      { tenantId: tenant.id, resourceId: pay.resource.id, outcome: "issued", createdAt: old },
      // Another tenant's events never count (resource_id has no FK).
      { tenantId: other.id, resourceId: pay.resource.id, outcome: "issued" },
    ]);

    const list = await listResources(tenant.id);
    expect(list.map((r) => [r.name, r.scopeCount, r.appCount, r.tokens24h])).toEqual([
      ["A-payments", 2, 2, 2],
      ["B-empty", 0, 0, 0],
    ]);
    expect(await listResources(other.id)).toEqual([]);
  });
});

describe("getResourceDetail", () => {
  it("includes scopes with grantedAppCount and applications with access", async () => {
    const tenant = await createTenant();
    const pay = await createResourceWithScopes(tenant.id, PAYMENTS, ["p:write", "p:read"]);
    const app1 = (await createApplication(tenant.id, { name: "alpha" })).application;
    const app2 = (await createApplication(tenant.id, { name: "beta" })).application;
    await createApplication(tenant.id, { name: "gamma" });
    await grant(tenant.id, app1.id, [pay.scopes[0].id, pay.scopes[1].id]);
    await grant(tenant.id, app2.id, [pay.scopes[1].id]);

    const d = await getResourceDetail(tenant.id, pay.resource.id);
    expect(d.id).toBe(pay.resource.id);
    expect(d.scopes.map((s) => [s.name, s.grantedAppCount, s.agentPolicy])).toEqual([
      ["p:read", 2, "auto"],
      ["p:write", 1, "auto"],
    ]);
    expect(d.applications).toEqual([
      { id: app1.id, name: "alpha", clientId: app1.clientId },
      { id: app2.id, name: "beta", clientId: app2.clientId },
    ]);
  });

  it("404 for unknown, non-UUID or foreign-tenant ids", async () => {
    const a = await createTenant();
    const b = await createTenant();
    const { resource } = await createResourceWithScopes(b.id, PAYMENTS, []);
    for (const id of [resource.id, "not-a-uuid", crypto.randomUUID()]) {
      const err = await apiErrorOf(getResourceDetail(a.id, id));
      expect([err.statusCode, err.errorCode]).toEqual([404, "resource_not_found"]);
    }
  });
});

describe("updateResource", () => {
  it("updates fields; ttl can be cleared; empty patch is a no-op", async () => {
    const tenant = await createTenant();
    const r = await createResource(tenant.id, {
      name: "Payments",
      audience: PAYMENTS,
      tokenTtlSeconds: 600,
    });
    const u = await updateResource(tenant.id, r.id, { kind: "mcp", tokenTtlSeconds: null });
    expect(u).toMatchObject({ name: "Payments", kind: "mcp", tokenTtlSeconds: null });
    expect(await updateResource(tenant.id, r.id, {})).toMatchObject({ kind: "mcp" });
  });

  it("audience taken by another resource of the tenant → 409; other tenant's audience is fine", async () => {
    const a = await createTenant();
    const b = await createTenant();
    await createResource(a.id, { name: "One", audience: PAYMENTS });
    await createResource(b.id, { name: "B", audience: "urn:acme:b" });
    const two = await createResource(a.id, { name: "Two", audience: "urn:acme:two" });
    const err = await apiErrorOf(updateResource(a.id, two.id, { audience: PAYMENTS }));
    expect([err.statusCode, err.errorCode]).toEqual([409, "audience_exists"]);
    await expect(updateResource(a.id, two.id, { audience: "urn:acme:b" })).resolves.toMatchObject({
      audience: "urn:acme:b",
    });
  });

  it("foreign-tenant id → 404", async () => {
    const a = await createTenant();
    const b = await createTenant();
    const r = await createResource(b.id, { name: "B", audience: PAYMENTS });
    const err = await apiErrorOf(updateResource(a.id, r.id, { name: "hijack" }));
    expect(err.errorCode).toBe("resource_not_found");
  });
});

describe("deleteResource", () => {
  it("cascades scopes and grants; second delete → 404", async () => {
    const tenant = await createTenant();
    const pay = await createResourceWithScopes(tenant.id, PAYMENTS, ["p:read", "p:write"]);
    const keep = await createResourceWithScopes(tenant.id, "urn:acme:keep", ["k:read"]);
    const { application } = await createApplication(tenant.id);
    await grant(
      tenant.id,
      application.id,
      [...pay.scopes, ...keep.scopes].map((s) => s.id),
    );

    await deleteResource(tenant.id, pay.resource.id);

    const grants = await db
      .select()
      .from(applicationGrants)
      .where(eq(applicationGrants.applicationId, application.id));
    expect(grants.map((g) => g.scopeId)).toEqual([keep.scopes[0].id]);
    const left = await db.select().from(scopes).where(eq(scopes.tenantId, tenant.id));
    expect(left.map((s) => s.name)).toEqual(["k:read"]);

    const err = await apiErrorOf(deleteResource(tenant.id, pay.resource.id));
    expect(err.errorCode).toBe("resource_not_found");
  });
});
