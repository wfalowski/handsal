import { applicationGrants, db, pool, runMigrations, scopes } from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import {
  addMember,
  createAdminUser,
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../../test/factories.js";
import { formRequest, jsonRequest, loginAs } from "../../test/helpers.js";

const PAYMENTS = "https://api.acme.io/payments";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

/** Tenant + logged-in member with `role`; `call` sends cookie + CSRF on every request. */
async function setup(role: TenantRole = "admin") {
  const tenant = await createTenant();
  const { user, password } = await createAdminUser();
  await addMember(tenant.id, user.id, role);
  const { cookie, csrf } = await loginAs(app, user.email, password);
  const base = `/api/tenants/${tenant.id}/resources`;
  const call = (method: string, path: string, body?: unknown) =>
    jsonRequest(app, method, `${base}${path}`, body, { cookie, "x-csrf-token": csrf });
  return { tenant, user, call };
}

describe("resources CRUD", () => {
  it("POST → 201, GET list, GET detail, PATCH, DELETE → 204, then 404", async () => {
    const { call } = await setup();

    const created = await call("POST", "", { name: "Payments", audience: PAYMENTS });
    expect(created.status).toBe(201);
    const r = await created.json();
    expect(r).toMatchObject({ name: "Payments", kind: "api", audience: PAYMENTS });

    const list = await call("GET", "");
    expect(list.status).toBe(200);
    expect(await list.json()).toEqual([{ ...r, scopeCount: 0, appCount: 0, tokens24h: 0 }]);

    const detail = await call("GET", `/${r.id}`);
    expect(await detail.json()).toEqual({ ...r, scopes: [], applications: [] });

    const patched = await call("PATCH", `/${r.id}`, { kind: "mcp", tokenTtlSeconds: 900 });
    expect(patched.status).toBe(200);
    expect(await patched.json()).toMatchObject({ kind: "mcp", tokenTtlSeconds: 900 });

    expect((await call("DELETE", `/${r.id}`)).status).toBe(204);
    const gone = await call("GET", `/${r.id}`);
    expect(gone.status).toBe(404);
    expect((await gone.json()).error).toBe("resource_not_found");
  });

  it("invalid body → 400 validation_error", async () => {
    const { call } = await setup();
    const res = await call("POST", "", { name: "X", audience: "not a url" });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("validation_error");
  });

  it("duplicate audience → 409 audience_exists (create and update); other tenant OK", async () => {
    const { call } = await setup();
    await call("POST", "", { name: "One", audience: PAYMENTS });
    const dup = await call("POST", "", { name: "Two", audience: PAYMENTS });
    expect(dup.status).toBe(409);
    expect((await dup.json()).error).toBe("audience_exists");

    const two = await (await call("POST", "", { name: "Two", audience: "urn:acme:two" })).json();
    const upd = await call("PATCH", `/${two.id}`, { audience: PAYMENTS });
    expect(upd.status).toBe(409);
    expect((await upd.json()).error).toBe("audience_exists");

    const other = await setup();
    expect((await other.call("POST", "", { name: "One", audience: PAYMENTS })).status).toBe(201);
  });

  it("list counts reflect grants and a real token issue", async () => {
    const { tenant, call } = await setup();
    const { resource, scopes: sc } = await createResourceWithScopes(tenant.id, PAYMENTS, [
      "p:read",
      "p:write",
    ]);
    const { application, clientSecret } = await createApplication(tenant.id);
    const second = (await createApplication(tenant.id)).application;
    await grant(tenant.id, application.id, [sc[0].id, sc[1].id]);
    await grant(tenant.id, second.id, [sc[1].id]);

    const before = (await (await call("GET", "")).json())[0];
    expect(before).toMatchObject({ id: resource.id, scopeCount: 2, appCount: 2, tokens24h: 0 });

    const token = await formRequest(
      app,
      `/t/${tenant.slug}/oauth/token`,
      { grant_type: "client_credentials", resource: PAYMENTS },
      {
        Authorization: `Basic ${Buffer.from(`${application.clientId}:${clientSecret}`).toString("base64")}`,
      },
    );
    expect(token.status).toBe(200);

    const after = (await (await call("GET", "")).json())[0];
    expect(after.tokens24h).toBe(1);

    const detail = await (await call("GET", `/${resource.id}`)).json();
    expect(
      detail.scopes.map((s: { name: string; grantedAppCount: number }) => [
        s.name,
        s.grantedAppCount,
      ]),
    ).toEqual([
      ["p:read", 1],
      ["p:write", 2],
    ]);
    expect(detail.applications.map((a: { id: string }) => a.id).sort()).toEqual(
      [application.id, second.id].sort(),
    );
  });

  it("DELETE cascades scopes and grants", async () => {
    const { tenant, call } = await setup();
    const { resource } = await createResourceWithScopes(tenant.id, PAYMENTS, ["a", "b"]);
    const { application } = await createApplication(tenant.id);
    const scopeIds = (await db.select().from(scopes)).map((s) => s.id);
    await grant(tenant.id, application.id, scopeIds);
    expect(await db.$count(applicationGrants)).toBe(2);

    expect((await call("DELETE", `/${resource.id}`)).status).toBe(204);
    expect(await db.$count(applicationGrants)).toBe(0);
    expect(await db.$count(scopes, eq(scopes.resourceId, resource.id))).toBe(0);
  });
});

describe("access control", () => {
  it("auditor can read but every mutation → 403", async () => {
    const { tenant, call } = await setup("auditor");
    const { resource } = await createResourceWithScopes(tenant.id, PAYMENTS, ["a"]);
    expect((await call("GET", "")).status).toBe(200);
    expect((await call("GET", `/${resource.id}`)).status).toBe(200);
    expect((await call("GET", `/${resource.id}/scopes`)).status).toBe(200);

    for (const [method, path, body] of [
      ["POST", "", { name: "X", audience: "urn:acme:x" }],
      ["PATCH", `/${resource.id}`, { name: "Y" }],
      ["DELETE", `/${resource.id}`, undefined],
    ] as const) {
      const res = await call(method, path, body);
      expect(res.status).toBe(403);
      expect((await res.json()).error).toBe("forbidden");
    }
  });

  it("non-member → 404 tenant_not_found", async () => {
    const tenant = await createTenant();
    const { user, password } = await createAdminUser();
    const { cookie } = await loginAs(app, user.email, password);
    const res = await jsonRequest(app, "GET", `/api/tenants/${tenant.id}/resources`, undefined, {
      cookie,
    });
    expect(res.status).toBe(404);
    expect((await res.json()).error).toBe("tenant_not_found");
  });

  it("unauthenticated → 401", async () => {
    const tenant = await createTenant();
    const res = await jsonRequest(app, "GET", `/api/tenants/${tenant.id}/resources`);
    expect(res.status).toBe(401);
  });

  it("tenant isolation: tenant B's resource under tenant A → 404 (read, patch, delete)", async () => {
    const { call } = await setup();
    const b = await createTenant();
    const { resource } = await createResourceWithScopes(b.id, PAYMENTS, ["a"]);
    for (const [method, body] of [
      ["GET", undefined],
      ["PATCH", { name: "hijack" }],
      ["DELETE", undefined],
    ] as const) {
      const res = await call(method, `/${resource.id}`, body);
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe("resource_not_found");
    }
    expect((await call("GET", "/not-a-uuid")).status).toBe(404);
  });
});
