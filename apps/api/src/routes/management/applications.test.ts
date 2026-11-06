import { applications, db, pool, runMigrations } from "@handsal/db";
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

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

type Session = Record<string, string>;

async function sessionFor(tenantId: string | null, role?: "owner" | "admin" | "auditor") {
  const { user, password } = await createAdminUser();
  if (tenantId && role) await addMember(tenantId, user.id, role);
  const { cookie, csrf } = await loginAs(app, user.email, password);
  return { user, headers: { cookie, "x-csrf-token": csrf } as Session };
}

async function setup() {
  const tenant = await createTenant();
  const admin = await sessionFor(tenant.id, "admin");
  const base = `/api/tenants/${tenant.id}/applications`;
  return { tenant, admin, base };
}

const req = (method: string, path: string, headers: Session, body?: unknown) =>
  jsonRequest(app, method, path, body, headers);

describe("applications CRUD", () => {
  it("create → 201 with the secret once; get/list never expose it", async () => {
    const { tenant, admin, base } = await setup();
    const res = await req("POST", base, admin.headers, {
      name: "billing-worker",
      description: "Bills",
      tokenTtlSeconds: 600,
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(typeof body.clientSecret).toBe("string");
    expect(body.application).toMatchObject({
      name: "billing-worker",
      description: "Bills",
      kind: "service",
      tokenEndpointAuthMethod: "client_secret_basic",
      tokenTtlSeconds: 600,
      status: "active",
    });
    const [row] = await db
      .select()
      .from(applications)
      .where(eq(applications.id, body.application.id));
    expect(row.createdBy).toBe(admin.user.id);
    expect(row.tenantId).toBe(tenant.id);

    const list = await req("GET", base, admin.headers);
    const detail = await req("GET", `${base}/${body.application.id}`, admin.headers);
    for (const r of [list, detail]) {
      expect(r.status).toBe(200);
      const text = await r.text();
      expect(text).not.toContain(body.clientSecret);
      expect(text).not.toMatch(/secretHash|clientSecret"/);
    }
  });

  it("kind in the create body → 400 validation_error", async () => {
    const { admin, base } = await setup();
    const res = await req("POST", base, admin.headers, { name: "agent", kind: "agent" });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("validation_error");
  });

  it("invalid create body → 400; duplicate name → 409", async () => {
    const { admin, base } = await setup();
    expect((await req("POST", base, admin.headers, { name: "" })).status).toBe(400);
    expect((await req("POST", base, admin.headers, { name: "dup" })).status).toBe(201);
    const dup = await req("POST", base, admin.headers, { name: "dup" });
    expect(dup.status).toBe(409);
    expect((await dup.json()).error).toBe("application_exists");
  });

  it("GET :appId returns application, grants, issuer, tokenEndpoint, recentTokens", async () => {
    const { tenant, admin, base } = await setup();
    const { application, clientSecret } = await createApplication(tenant.id);
    const { resource, scopes } = await createResourceWithScopes(tenant.id, "https://api.x/pay", [
      "pay:read",
    ]);
    await grant(tenant.id, application.id, [scopes[0].id]);

    const empty = await (await req("GET", `${base}/${application.id}`, admin.headers)).json();
    expect(empty).toEqual({
      application,
      grants: [
        {
          resource: {
            id: resource.id,
            name: resource.name,
            audience: "https://api.x/pay",
            kind: resource.kind,
          },
          scopes: [{ id: scopes[0].id, name: "pay:read" }],
        },
      ],
      issuer: `https://test.example.com/t/${tenant.slug}`,
      tokenEndpoint: `https://test.example.com/t/${tenant.slug}/oauth/token`,
      recentTokens: [],
    });

    const tokenRes = await formRequest(
      app,
      `/t/${tenant.slug}/oauth/token`,
      { grant_type: "client_credentials", resource: "https://api.x/pay", scope: "pay:read" },
      {
        Authorization: `Basic ${Buffer.from(`${application.clientId}:${clientSecret}`).toString("base64")}`,
      },
    );
    expect(tokenRes.status).toBe(200);

    const body = await (await req("GET", `${base}/${application.id}`, admin.headers)).json();
    expect(body.recentTokens).toHaveLength(1);
    expect(body.recentTokens[0]).toMatchObject({
      applicationId: application.id,
      outcome: "issued",
      audience: "https://api.x/pay",
    });
  });

  it("recentTokens is capped at 5", async () => {
    const { tenant, admin, base } = await setup();
    const { application, clientSecret } = await createApplication(tenant.id);
    await createResourceWithScopes(tenant.id, "https://api.x/a", ["a"]);
    const auth = `Basic ${Buffer.from(`${application.clientId}:${clientSecret}`).toString("base64")}`;
    for (let i = 0; i < 6; i++) {
      // Not granted → denied events are recorded too.
      await formRequest(
        app,
        `/t/${tenant.slug}/oauth/token`,
        { grant_type: "client_credentials", resource: "https://api.x/a" },
        { Authorization: auth },
      );
    }
    const body = await (await req("GET", `${base}/${application.id}`, admin.headers)).json();
    expect(body.recentTokens).toHaveLength(5);
  });

  it("PATCH updates fields", async () => {
    const { tenant, admin, base } = await setup();
    const { application } = await createApplication(tenant.id, { description: "old" });
    const res = await req("PATCH", `${base}/${application.id}`, admin.headers, {
      name: "renamed",
      description: null,
      tokenEndpointAuthMethod: "client_secret_post",
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      id: application.id,
      name: "renamed",
      description: null,
      tokenEndpointAuthMethod: "client_secret_post",
    });
    const bad = await req("PATCH", `${base}/${application.id}`, admin.headers, {
      tokenEndpointAuthMethod: "private_key_jwt",
    });
    expect(bad.status).toBe(400);
  });

  it("DELETE → 204, then 404", async () => {
    const { tenant, admin, base } = await setup();
    const { application } = await createApplication(tenant.id);
    const res = await req("DELETE", `${base}/${application.id}`, admin.headers);
    expect(res.status).toBe(204);
    const again = await req("GET", `${base}/${application.id}`, admin.headers);
    expect(again.status).toBe(404);
    expect((await again.json()).error).toBe("application_not_found");
  });

  it("rotate-secret returns {clientSecret, previousSecretExpiresAt}", async () => {
    const { tenant, admin, base } = await setup();
    const { application, clientSecret } = await createApplication(tenant.id);

    const res = await req("POST", `${base}/${application.id}/rotate-secret`, admin.headers, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["clientSecret", "previousSecretExpiresAt"]);
    expect(body.clientSecret).not.toBe(clientSecret);
    const expiresIn = new Date(body.previousSecretExpiresAt).getTime() - Date.now();
    expect(expiresIn).toBeGreaterThan(86_000_000); // default grace 86400s
    expect(expiresIn).toBeLessThanOrEqual(86_400_000);

    const immediate = await req("POST", `${base}/${application.id}/rotate-secret`, admin.headers, {
      graceSeconds: 0,
    });
    expect((await immediate.json()).previousSecretExpiresAt).toBeNull();

    const tooLong = await req("POST", `${base}/${application.id}/rotate-secret`, admin.headers, {
      graceSeconds: 604801,
    });
    expect(tooLong.status).toBe(400);

    const detail = await (await req("GET", `${base}/${application.id}`, admin.headers)).text();
    expect(detail).not.toContain(body.clientSecret);
  });

  it("disable / enable / revoke-all-tokens return the ApplicationDto", async () => {
    const { tenant, admin, base } = await setup();
    const { application } = await createApplication(tenant.id);

    const disabled = await req("POST", `${base}/${application.id}/disable`, admin.headers);
    expect(disabled.status).toBe(200);
    expect((await disabled.json()).status).toBe("disabled");

    const enabled = await req("POST", `${base}/${application.id}/enable`, admin.headers);
    expect((await enabled.json()).status).toBe("active");

    const revoked = await req("POST", `${base}/${application.id}/revoke-all-tokens`, admin.headers);
    expect(revoked.status).toBe(200);
    const dto = await revoked.json();
    expect(dto.id).toBe(application.id);
    expect(dto.tokensNotBefore).not.toBeNull();
  });
});

describe("list filters", () => {
  it("q matches name or client_id; status filters active/disabled/needs_attention", async () => {
    const { tenant, admin, base } = await setup();
    const alpha = (await createApplication(tenant.id, { name: "alpha-svc" })).application;
    const beta = (await createApplication(tenant.id, { name: "beta-svc" })).application;
    const gamma = (await createApplication(tenant.id, { name: "gamma-svc" })).application;
    await req("POST", `${base}/${beta.id}/disable`, admin.headers);
    await req("POST", `${base}/${gamma.id}/rotate-secret`, admin.headers, { graceSeconds: 3600 });

    const names = async (query: string) => {
      const res = await req("GET", `${base}${query}`, admin.headers);
      expect(res.status).toBe(200);
      return ((await res.json()).items as { name: string }[]).map((a) => a.name);
    };

    expect(await names("")).toEqual(["alpha-svc", "beta-svc", "gamma-svc"]);
    expect(await names("?q=ALPHA")).toEqual(["alpha-svc"]);
    expect(await names(`?q=${alpha.clientId}`)).toEqual(["alpha-svc"]);
    expect(await names("?status=active")).toEqual(["alpha-svc", "gamma-svc"]);
    expect(await names("?status=disabled")).toEqual(["beta-svc"]);
    expect(await names("?status=needs_attention")).toEqual(["beta-svc", "gamma-svc"]);

    const items = (await (await req("GET", base, admin.headers)).json()).items;
    expect(items[0]).toMatchObject({ resourceCount: 0, scopeNames: [] });
  });

  it("unknown status → 400 validation_error", async () => {
    const { admin, base } = await setup();
    const res = await req("GET", `${base}?status=bogus`, admin.headers);
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("validation_error");
  });
});

describe("access control and isolation", () => {
  it("auditor can GET but every mutation → 403", async () => {
    const { tenant, base } = await setup();
    const { application } = await createApplication(tenant.id);
    const auditor = await sessionFor(tenant.id, "auditor");
    const a = `${base}/${application.id}`;

    expect((await req("GET", base, auditor.headers)).status).toBe(200);
    expect((await req("GET", a, auditor.headers)).status).toBe(200);
    expect((await req("GET", `${a}/grants`, auditor.headers)).status).toBe(200);

    const mutations: [string, string, unknown?][] = [
      ["POST", base, { name: "x" }],
      ["PATCH", a, { name: "y" }],
      ["DELETE", a],
      ["POST", `${a}/rotate-secret`, {}],
      ["POST", `${a}/disable`],
      ["POST", `${a}/enable`],
      ["POST", `${a}/revoke-all-tokens`],
      ["PUT", `${a}/grants`, { scopeIds: [] }],
    ];
    for (const [method, path, body] of mutations) {
      const res = await req(method, path, auditor.headers, body);
      expect(res.status, `${method} ${path}`).toBe(403);
      expect((await res.json()).error).toBe("forbidden");
    }
  });

  it("non-member → 404 tenant_not_found on every route", async () => {
    const { tenant, base } = await setup();
    const { application } = await createApplication(tenant.id);
    const outsider = await sessionFor(null);
    const a = `${base}/${application.id}`;
    const routes: [string, string, unknown?][] = [
      ["GET", base],
      ["POST", base, { name: "x" }],
      ["GET", a],
      ["PATCH", a, { name: "y" }],
      ["DELETE", a],
      ["POST", `${a}/rotate-secret`, {}],
      ["POST", `${a}/disable`],
      ["POST", `${a}/enable`],
      ["POST", `${a}/revoke-all-tokens`],
      ["GET", `${a}/grants`],
      ["PUT", `${a}/grants`, { scopeIds: [] }],
    ];
    for (const [method, path, body] of routes) {
      const res = await req(method, path, outsider.headers, body);
      expect(res.status, `${method} ${path}`).toBe(404);
      expect((await res.json()).error).toBe("tenant_not_found");
    }
  });

  it("app of tenant B under tenant A → 404 application_not_found", async () => {
    const { tenant, admin, base } = await setup();
    const other = await createTenant();
    await addMember(other.id, admin.user.id, "admin");
    const { application } = await createApplication(other.id);
    const a = `${base}/${application.id}`;
    const routes: [string, string, unknown?][] = [
      ["GET", a],
      ["PATCH", a, { name: "y" }],
      ["DELETE", a],
      ["POST", `${a}/rotate-secret`, {}],
      ["POST", `${a}/disable`],
      ["POST", `${a}/enable`],
      ["POST", `${a}/revoke-all-tokens`],
      ["GET", `${a}/grants`],
      ["PUT", `${a}/grants`, { scopeIds: [] }],
    ];
    for (const [method, path, body] of routes) {
      const res = await req(method, path, admin.headers, body);
      expect(res.status, `${method} ${path}`).toBe(404);
      expect((await res.json()).error).toBe("application_not_found");
    }
    const [row] = await db.select().from(applications).where(eq(applications.id, application.id));
    expect(row.status).toBe("active");
    expect(tenant.id).not.toBe(other.id);
  });

  it("non-UUID appId → 404 application_not_found", async () => {
    const { admin, base } = await setup();
    const res = await req("GET", `${base}/not-a-uuid`, admin.headers);
    expect(res.status).toBe(404);
    expect((await res.json()).error).toBe("application_not_found");
  });

  it("mutation without CSRF token → 403 csrf_required", async () => {
    const { admin, base } = await setup();
    const res = await req("POST", base, { cookie: admin.headers.cookie }, { name: "x" });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("csrf_required");
  });
});
