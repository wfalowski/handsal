import { pool, runMigrations } from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import {
  addMember,
  createAdminUser,
  createResourceWithScopes,
  createTenant,
  truncateAll,
} from "../../test/factories.js";
import { jsonRequest, loginAs } from "../../test/helpers.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

async function setup(role: TenantRole = "admin") {
  const tenant = await createTenant();
  const { user, password } = await createAdminUser();
  await addMember(tenant.id, user.id, role);
  const { cookie, csrf } = await loginAs(app, user.email, password);
  const pay = (await createResourceWithScopes(tenant.id, "https://api.acme.io/payments", []))
    .resource;
  const inv = (await createResourceWithScopes(tenant.id, "https://api.acme.io/invoices", []))
    .resource;
  const call = (method: string, resourceId: string, path: string, body?: unknown) =>
    jsonRequest(
      app,
      method,
      `/api/tenants/${tenant.id}/resources/${resourceId}/scopes${path}`,
      body,
      {
        cookie,
        "x-csrf-token": csrf,
      },
    );
  return { tenant, pay, inv, call };
}

describe("scopes CRUD", () => {
  it("POST → 201, GET list, PATCH, DELETE → 204", async () => {
    const { pay, call } = await setup();
    const created = await call("POST", pay.id, "", { name: "payments:read", description: "Read" });
    expect(created.status).toBe(201);
    const s = await created.json();
    expect(s).toMatchObject({
      resourceId: pay.id,
      name: "payments:read",
      description: "Read",
      agentPolicy: "auto",
    });

    const list = await call("GET", pay.id, "");
    expect(list.status).toBe(200);
    expect(await list.json()).toEqual([s]);

    const patched = await call("PATCH", pay.id, `/${s.id}`, {
      description: null,
      agentPolicy: "approval",
    });
    expect(patched.status).toBe(200);
    expect(await patched.json()).toMatchObject({ description: null, agentPolicy: "approval" });

    expect((await call("DELETE", pay.id, `/${s.id}`)).status).toBe(204);
    expect(await (await call("GET", pay.id, "")).json()).toEqual([]);
    const again = await call("DELETE", pay.id, `/${s.id}`);
    expect(again.status).toBe(404);
    expect((await again.json()).error).toBe("scope_not_found");
  });

  it("agentPolicy is accepted on create", async () => {
    const { pay, call } = await setup();
    const res = await call("POST", pay.id, "", { name: "x", agentPolicy: "never" });
    expect((await res.json()).agentPolicy).toBe("never");
  });

  it("invalid scope name → 400", async () => {
    const { pay, call } = await setup();
    const res = await call("POST", pay.id, "", { name: "has space" });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("validation_error");
  });

  it("duplicate name within resource → 409 scope_exists; same name on another resource OK", async () => {
    const { pay, inv, call } = await setup();
    expect((await call("POST", pay.id, "", { name: "read" })).status).toBe(201);
    const dup = await call("POST", pay.id, "", { name: "read" });
    expect(dup.status).toBe(409);
    expect((await dup.json()).error).toBe("scope_exists");
    expect((await call("POST", inv.id, "", { name: "read" })).status).toBe(201);
  });
});

describe("access control", () => {
  it("auditor → 403 on mutations", async () => {
    const { tenant, call } = await setup("auditor");
    const { resource, scopes } = await createResourceWithScopes(tenant.id, "urn:acme:x", ["a"]);
    for (const [method, path, body] of [
      ["POST", "", { name: "b" }],
      ["PATCH", `/${scopes[0].id}`, { name: "c" }],
      ["DELETE", `/${scopes[0].id}`, undefined],
    ] as const) {
      expect((await call(method, resource.id, path, body)).status).toBe(403);
    }
  });

  it("tenant B's resource / scope under tenant A → 404", async () => {
    const { call } = await setup();
    const b = await createTenant();
    const { resource, scopes } = await createResourceWithScopes(b.id, "urn:acme:b", ["a"]);
    const list = await call("GET", resource.id, "");
    expect(list.status).toBe(404);
    expect((await list.json()).error).toBe("resource_not_found");
    expect((await call("POST", resource.id, "", { name: "x" })).status).toBe(404);
    expect((await call("PATCH", resource.id, `/${scopes[0].id}`, { name: "x" })).status).toBe(404);
    expect((await call("DELETE", resource.id, `/${scopes[0].id}`)).status).toBe(404);
  });

  it("scope of another resource in the same tenant → 404 scope_not_found", async () => {
    const { pay, inv, call } = await setup();
    const s = await (await call("POST", pay.id, "", { name: "read" })).json();
    const res = await call("PATCH", inv.id, `/${s.id}`, { name: "x" });
    expect(res.status).toBe(404);
    expect((await res.json()).error).toBe("scope_not_found");
  });
});
