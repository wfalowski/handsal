import { pool, runMigrations } from "@handsal/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import { addMember, createAdminUser, createTenant, truncateAll } from "../../test/factories.js";
import { loginAs } from "../../test/helpers.js";

beforeAll(async () => {
  await runMigrations();
});
beforeEach(async () => {
  await truncateAll();
});
afterAll(async () => {
  await pool.end();
});

async function actor(tenantId: string, role: "auditor" | "admin") {
  const { user, password } = await createAdminUser();
  await addMember(tenantId, user.id, role);
  const { cookie, csrf } = await loginAs(app, user.email, password);
  return { cookie, "x-csrf-token": csrf };
}

const noPem = (body: unknown) => expect(JSON.stringify(body)).not.toMatch(/PRIVATE|"d":/);

describe("signing keys", () => {
  it("auditor can list; no PEM in the response", async () => {
    const tenant = await createTenant();
    const headers = await actor(tenant.id, "auditor");
    const res = await app.request(`/api/tenants/${tenant.id}/signing-keys`, { headers });
    expect(res.status).toBe(200);
    const body = await res.json();
    noPem(body);
    expect(body.items).toEqual([]);
  });

  it("rotate as auditor → 403", async () => {
    const tenant = await createTenant();
    const headers = await actor(tenant.id, "auditor");
    const res = await app.request(`/api/tenants/${tenant.id}/signing-keys/rotate`, {
      method: "POST",
      headers,
    });
    expect(res.status).toBe(403);
  });

  it("rotate as admin → 201, then list shows one active + one retiring", async () => {
    const tenant = await createTenant();
    const headers = await actor(tenant.id, "admin");
    const url = `/api/tenants/${tenant.id}/signing-keys`;
    // No key exists yet: the first rotate creates the initial one, the second retires it.
    expect((await app.request(`${url}/rotate`, { method: "POST", headers })).status).toBe(201);
    const res = await app.request(`${url}/rotate`, { method: "POST", headers });
    expect(res.status).toBe(201);
    const created = await res.json();
    noPem(created);
    expect(created).toMatchObject({ status: "active", algorithm: "ES256", retiresAt: null });
    expect(Object.keys(created).sort()).toEqual(
      ["algorithm", "createdAt", "id", "kid", "retiresAt", "status"].sort(),
    );

    const body = await (await app.request(url, { headers })).json();
    noPem(body);
    const statuses = body.items.map((k: { status: string }) => k.status).sort();
    expect(statuses).toEqual(["active", "retiring"]);
    expect(body.items.find((k: { status: string }) => k.status === "retiring").retiresAt).toEqual(
      expect.any(String),
    );
  });
});
