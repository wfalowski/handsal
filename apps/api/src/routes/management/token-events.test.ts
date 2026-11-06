import { randomUUID } from "node:crypto";
import { pool, runMigrations } from "@handsal/db";
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
import { formRequest, loginAs } from "../../test/helpers.js";

beforeAll(async () => {
  await runMigrations();
});
beforeEach(async () => {
  await truncateAll();
});
afterAll(async () => {
  await pool.end();
});

const AUD = "https://api.acme.io/payments";
const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
const noPem = (body: unknown) => expect(JSON.stringify(body)).not.toMatch(/PRIVATE|"d":/);

async function setup() {
  const tenant = await createTenant();
  const { resource, scopes } = await createResourceWithScopes(tenant.id, AUD, ["payments:read"]);
  const { user, password } = await createAdminUser();
  await addMember(tenant.id, user.id, "auditor");
  const { cookie } = await loginAs(app, user.email, password);

  async function newApp() {
    const { application, clientSecret } = await createApplication(tenant.id);
    await grant(tenant.id, application.id, [scopes[0].id]);
    return { application, clientSecret };
  }
  const token = (a: { application: { clientId: string }; clientSecret: string }, secret?: string) =>
    formRequest(
      app,
      `/t/${tenant.slug}/oauth/token`,
      { grant_type: "client_credentials", resource: AUD, scope: "payments:read" },
      { Authorization: basic(a.application.clientId, secret ?? a.clientSecret) },
    );
  const get = (path: string) =>
    app.request(`/api/tenants/${tenant.id}${path}`, { headers: { cookie } });
  return { tenant, resource, newApp, token, get };
}

describe("token events", () => {
  it("paginates with a cursor, no overlap, last page has nextCursor null", async () => {
    const s = await setup();
    const a = await s.newApp();
    for (let i = 0; i < 3; i++) expect((await s.token(a)).status).toBe(200);

    const r1 = await s.get("/token-events?limit=2");
    expect(r1.status).toBe(200);
    const p1 = await r1.json();
    noPem(p1);
    expect(p1.items).toHaveLength(2);
    expect(p1.nextCursor).toEqual(expect.any(String));

    const p2 = await (
      await s.get(`/token-events?limit=2&cursor=${encodeURIComponent(p1.nextCursor)}`)
    ).json();
    expect(p2.items).toHaveLength(1);
    expect(p2.nextCursor).toBeNull();
    const ids = [...p1.items, ...p2.items].map((e: { id: string }) => e.id);
    expect(new Set(ids).size).toBe(3);
  });

  it("filters by outcome", async () => {
    const s = await setup();
    const a = await s.newApp();
    await s.token(a);
    await s.token(a, "wrong-secret");
    const body = await (await s.get("/token-events?outcome=denied")).json();
    noPem(body);
    expect(body.items).toHaveLength(1);
    expect(body.items[0].outcome).toBe("denied");
  });

  it("stats match the events created", async () => {
    const s = await setup();
    const a = await s.newApp();
    await s.token(a);
    await s.token(a);
    await s.token(a, "wrong-secret");
    const res = await s.get("/token-events/stats");
    expect(res.status).toBe(200);
    const body = await res.json();
    noPem(body);
    expect(body).toEqual({
      issued24h: 2,
      issuedPrev24h: 0,
      denied24h: 1,
      requests24h: 3,
      activeApps24h: 1,
      totalApps: 1,
    });
  });

  it("app-scoped list excludes other apps", async () => {
    const s = await setup();
    const a = await s.newApp();
    const b = await s.newApp();
    await s.token(a);
    await s.token(b);
    await s.token(b);

    const res = await s.get(`/applications/${b.application.id}/token-events?limit=10`);
    expect(res.status).toBe(200);
    const body = await res.json();
    noPem(body);
    expect(body.items).toHaveLength(2);
    expect(
      body.items.every((e: { applicationId: string }) => e.applicationId === b.application.id),
    ).toBe(true);
  });

  it("app-scoped list: unknown / non-uuid / other-tenant app → 404 application_not_found", async () => {
    const s = await setup();
    const other = await createTenant();
    const { application } = await createApplication(other.id);
    for (const id of [randomUUID(), "nope", application.id]) {
      const res = await s.get(`/applications/${id}/token-events`);
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe("application_not_found");
    }
  });

  it("invalid query → 400 validation_error", async () => {
    const s = await setup();
    for (const path of [
      "/token-events?limit=0",
      `/applications/${randomUUID()}/token-events?limit=0`,
    ]) {
      const res = await s.get(path);
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("validation_error");
    }
  });
});
