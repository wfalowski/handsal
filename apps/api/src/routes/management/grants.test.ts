import { applicationGrants, db, pool, runMigrations } from "@handsal/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import {
  addMember,
  createAdminUser,
  createApplication,
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

async function setup() {
  const tenant = await createTenant();
  const { user, password } = await createAdminUser();
  await addMember(tenant.id, user.id, "admin");
  const { cookie, csrf } = await loginAs(app, user.email, password);
  const headers = { cookie, "x-csrf-token": csrf };
  const { application } = await createApplication(tenant.id);
  const pay = await createResourceWithScopes(tenant.id, "https://api.x/pay", [
    "pay:write",
    "pay:read",
  ]);
  const crm = await createResourceWithScopes(tenant.id, "https://api.x/crm", ["crm:read"]);
  const url = `/api/tenants/${tenant.id}/applications/${application.id}/grants`;
  return { tenant, headers, application, pay, crm, url };
}

describe("PUT/GET …/applications/:appId/grants", () => {
  it("replaces the grant set and returns GrantView[] grouped by resource", async () => {
    const { headers, pay, crm, url } = await setup();
    const [write, read] = pay.scopes;

    const res = await jsonRequest(
      app,
      "PUT",
      url,
      { scopeIds: [write.id, read.id, crm.scopes[0].id, read.id] },
      headers,
    );
    expect(res.status).toBe(200);
    const expected = {
      grants: [
        {
          resource: {
            id: crm.resource.id,
            name: crm.resource.name,
            audience: "https://api.x/crm",
            kind: crm.resource.kind,
          },
          scopes: [{ id: crm.scopes[0].id, name: "crm:read" }],
        },
        {
          resource: {
            id: pay.resource.id,
            name: pay.resource.name,
            audience: "https://api.x/pay",
            kind: pay.resource.kind,
          },
          scopes: [
            { id: read.id, name: "pay:read" },
            { id: write.id, name: "pay:write" },
          ],
        },
      ].sort((a, b) => a.resource.name.localeCompare(b.resource.name)),
    };
    expect(await res.json()).toEqual(expected);

    const got = await jsonRequest(app, "GET", url, undefined, headers);
    expect(got.status).toBe(200);
    expect(await got.json()).toEqual(expected);

    // Replace, not merge.
    const replaced = await jsonRequest(app, "PUT", url, { scopeIds: [read.id] }, headers);
    expect((await replaced.json()).grants).toEqual([
      expect.objectContaining({ scopes: [{ id: read.id, name: "pay:read" }] }),
    ]);

    const cleared = await jsonRequest(app, "PUT", url, { scopeIds: [] }, headers);
    expect(await cleared.json()).toEqual({ grants: [] });
  });

  it("scope id from another tenant → 400 invalid_scope_ids, grants unchanged", async () => {
    const { headers, pay, url } = await setup();
    await jsonRequest(app, "PUT", url, { scopeIds: [pay.scopes[0].id] }, headers);

    const other = await createTenant();
    const foreign = await createResourceWithScopes(other.id, "https://api.y/z", ["z:read"]);
    const res = await jsonRequest(
      app,
      "PUT",
      url,
      { scopeIds: [pay.scopes[1].id, foreign.scopes[0].id] },
      headers,
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_scope_ids");
    expect(body.details).toEqual({ unknown: [foreign.scopes[0].id] });

    const rows = await db.select().from(applicationGrants);
    expect(rows.map((r) => r.scopeId)).toEqual([pay.scopes[0].id]);
  });

  it("invalid body → 400 validation_error", async () => {
    const { headers, url } = await setup();
    for (const body of [{}, { scopeIds: ["not-a-uuid"] }, { scopeIds: "x" }]) {
      const res = await jsonRequest(app, "PUT", url, body, headers);
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("validation_error");
    }
  });

  it("unknown application → 404 application_not_found", async () => {
    const { tenant, headers } = await setup();
    const url = `/api/tenants/${tenant.id}/applications/00000000-0000-4000-8000-000000000000/grants`;
    for (const [method, body] of [
      ["GET", undefined],
      ["PUT", { scopeIds: [] }],
    ] as const) {
      const res = await jsonRequest(app, method, url, body, headers);
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe("application_not_found");
    }
  });
});
