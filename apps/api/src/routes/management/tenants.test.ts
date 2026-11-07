import {
  applications,
  db,
  pool,
  runMigrations,
  scopes,
  signingKeys,
  tenantMembers,
  tenants,
} from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { count, eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import { env } from "../../env.js";
import { type AdminEnv, createAdminAuth, csrfProtection } from "../../middleware/admin-auth.js";
import { errorHandler } from "../../middleware/error-handler.js";
import {
  addMember,
  createAdminUser,
  createApplication,
  createResourceWithScopes,
  createTenant,
  truncateAll,
} from "../../test/factories.js";
import { jsonRequest, loginAs } from "../../test/helpers.js";
import { decryptPrivateKey } from "../../utils/crypto.js";
import { setOutboundLookupForTests } from "../../utils/outbound-url.js";
import { memberRoutes } from "./members.js";
import { tenantRoutes } from "./tenants.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

type Session = { cookie: string; csrf: string };

async function sessionFor(opts: { tenantId?: string; role?: TenantRole; superAdmin?: boolean }) {
  const { user, password } = await createAdminUser({ isSuperAdmin: opts.superAdmin ?? false });
  if (opts.tenantId && opts.role) await addMember(opts.tenantId, user.id, opts.role);
  return { user, ...(await loginAs(app, user.email, password)) };
}

const call = (s: Session, method: string, path: string, body?: unknown) =>
  jsonRequest(app, method, path, body, { cookie: s.cookie, "x-csrf-token": s.csrf });

const API_KEY = "k".repeat(40);
const apiKeyApp = new Hono<AdminEnv>();
apiKeyApp.use("*", createAdminAuth({ apiKey: API_KEY }), csrfProtection);
apiKeyApp.route("/api/tenants", tenantRoutes);
apiKeyApp.route("/api/tenants", memberRoutes);
apiKeyApp.onError(errorHandler);

const countOf = async (
  table: typeof applications | typeof scopes | typeof signingKeys | typeof tenantMembers,
  tenantId: string,
) => (await db.select({ n: count() }).from(table).where(eq(table.tenantId, tenantId)))[0].n;

const IDP = {
  issuer: "https://idp.example.com",
  jwksUri: "https://idp.example.com/jwks.json",
  audience: "handsal",
};

/** Every tenant-scoped route with a valid body for that route. */
const tenantRoutesFor = (t: { id: string; slug: string }, otherUserId: string) => ({
  reads: [
    ["GET", `/api/tenants/${t.id}`],
    ["GET", `/api/tenants/${t.id}/members`],
  ] as const,
  mutations: [
    ["PATCH", `/api/tenants/${t.id}`, { name: "Renamed", externalIdp: IDP }],
    ["POST", `/api/tenants/${t.id}/pause`, undefined],
    ["POST", `/api/tenants/${t.id}/resume`, undefined],
    ["POST", `/api/tenants/${t.id}/revoke-all-tokens`, undefined],
    ["DELETE", `/api/tenants/${t.id}`, { confirmSlug: t.slug }],
    ["POST", `/api/tenants/${t.id}/members`, { email: "x@example.com", role: "auditor" }],
    ["PATCH", `/api/tenants/${t.id}/members/${otherUserId}`, { role: "admin" }],
    ["DELETE", `/api/tenants/${t.id}/members/${otherUserId}`, undefined],
  ] as const,
});

describe("externalIdp", () => {
  it("PATCH sets and clears it; DTO emits null by default; http jwksUri → 400", async () => {
    const t = await createTenant();
    const s = await sessionFor({ tenantId: t.id, role: "admin" });
    const path = `/api/tenants/${t.id}`;
    expect((await (await call(s, "GET", path)).json()).externalIdp).toBeNull();

    const set = await call(s, "PATCH", path, { externalIdp: IDP });
    expect(set.status).toBe(200);
    expect((await set.json()).externalIdp).toEqual(IDP);
    expect((await (await call(s, "GET", path)).json()).externalIdp).toEqual(IDP);

    const bad = await call(s, "PATCH", path, {
      externalIdp: { ...IDP, jwksUri: "http://idp.example.com/jwks.json" },
    });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("validation_error");

    const cleared = await call(s, "PATCH", path, { externalIdp: null });
    expect((await cleared.json()).externalIdp).toBeNull();
  });
});

describe("approval webhook", () => {
  const SECRET = "whsec-0123456789abcdef";
  const URL_ = "https://hooks.example.com/handsal";

  it("PATCH sets url + secret (encrypted, never returned); null clears", async () => {
    const t = await createTenant();
    const s = await sessionFor({ tenantId: t.id, role: "admin" });
    const path = `/api/tenants/${t.id}`;
    const initial = await (await call(s, "GET", path)).json();
    expect(initial).toMatchObject({ approvalWebhookUrl: null, approvalWebhookSecretSet: false });

    const set = await call(s, "PATCH", path, {
      approvalWebhookUrl: URL_,
      approvalWebhookSecret: SECRET,
    });
    expect(set.status).toBe(200);
    const text = await set.text();
    expect(text).not.toContain(SECRET);
    expect(JSON.parse(text)).toMatchObject({
      approvalWebhookUrl: URL_,
      approvalWebhookSecretSet: true,
    });
    const [row] = await db.select().from(tenants).where(eq(tenants.id, t.id));
    expect(row.approvalWebhookSecretEnc).not.toContain(SECRET);
    expect(decryptPrivateKey(row.approvalWebhookSecretEnc ?? "", env.KEY_ENCRYPTION_SECRET)).toBe(
      SECRET,
    );

    // Omitted fields are left alone.
    const renamed = await (await call(s, "PATCH", path, { name: "Renamed" })).json();
    expect(renamed.approvalWebhookSecretSet).toBe(true);

    const cleared = await call(s, "PATCH", path, {
      approvalWebhookUrl: null,
      approvalWebhookSecret: null,
    });
    expect(await cleared.json()).toMatchObject({
      approvalWebhookUrl: null,
      approvalWebhookSecretSet: false,
    });
  });

  it("short secret and non-http(s) url → 400 validation_error", async () => {
    const t = await createTenant();
    const s = await sessionFor({ tenantId: t.id, role: "admin" });
    const path = `/api/tenants/${t.id}`;
    for (const body of [
      { approvalWebhookSecret: "short" },
      { approvalWebhookUrl: "ftp://hooks.example.com/x" },
    ]) {
      const res = await call(s, "PATCH", path, body);
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("validation_error");
    }
  });

  it("http webhook url rejected when NODE_ENV=production, allowed otherwise", async () => {
    const t = await createTenant();
    const path = `/api/tenants/${t.id}`;
    const auth = { authorization: `Bearer ${API_KEY}` };
    const body = { approvalWebhookUrl: "http://hooks.example.com/handsal" };
    expect((await jsonRequest(apiKeyApp, "PATCH", path, body, auth)).status).toBe(200);
    const prevNodeEnv = env.NODE_ENV;
    env.NODE_ENV = "production";
    // hooks.example.com does not resolve; production now checks DNS before saving.
    setOutboundLookupForTests(async () => [{ address: "192.0.2.1", family: 4 }]);
    try {
      const res = await jsonRequest(apiKeyApp, "PATCH", path, body, auth);
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("validation_error");
      const ok = await jsonRequest(apiKeyApp, "PATCH", path, { approvalWebhookUrl: URL_ }, auth);
      expect(ok.status).toBe(200);
    } finally {
      env.NODE_ENV = prevNodeEnv;
      setOutboundLookupForTests(null);
    }
  });
});

describe("authorization matrix", () => {
  it("auditor: GETs 200, every mutation 403", async () => {
    const t = await createTenant();
    const other = await createAdminUser();
    await addMember(t.id, other.user.id, "auditor");
    const s = await sessionFor({ tenantId: t.id, role: "auditor" });
    const { reads, mutations } = tenantRoutesFor(t, other.user.id);

    for (const [method, path] of reads) {
      expect((await call(s, method, path)).status, `${method} ${path}`).toBe(200);
    }
    for (const [method, path, body] of mutations) {
      const res = await call(s, method, path, body);
      expect(res.status, `${method} ${path}`).toBe(403);
      expect((await res.json()).error).toBe("forbidden");
    }
  });

  it("admin: may PATCH the tenant, but owner-only routes are 403", async () => {
    const t = await createTenant();
    const other = await createAdminUser();
    await addMember(t.id, other.user.id, "auditor");
    const s = await sessionFor({ tenantId: t.id, role: "admin" });
    const { mutations } = tenantRoutesFor(t, other.user.id);

    for (const [method, path, body] of mutations) {
      const res = await call(s, method, path, body);
      const expected = method === "PATCH" && path === `/api/tenants/${t.id}` ? 200 : 403;
      expect(res.status, `${method} ${path}`).toBe(expected);
    }
  });

  it("non-member: 404 on every tenant route (and invalid UUIDs 404)", async () => {
    const t = await createTenant();
    const other = await createAdminUser();
    await addMember(t.id, other.user.id, "owner");
    const s = await sessionFor({});
    const { reads, mutations } = tenantRoutesFor(t, other.user.id);

    for (const [method, path, body] of [
      ...reads.map(([m, p]) => [m, p, undefined]),
      ...mutations,
    ]) {
      const res = await call(s, method as string, path as string, body);
      expect(res.status, `${method} ${path}`).toBe(404);
      expect((await res.json()).error).toBe("tenant_not_found");
    }
    expect((await call(s, "GET", "/api/tenants/not-a-uuid")).status).toBe(404);
    expect(await db.select().from(tenants)).toHaveLength(1);
  });

  it("super-admin non-member: 200 on reads and owner routes", async () => {
    const t = await createTenant();
    const s = await sessionFor({ superAdmin: true });
    const detail = await call(s, "GET", `/api/tenants/${t.id}`);
    expect(detail.status).toBe(200);
    expect((await detail.json()).role).toBe("owner");
    expect((await call(s, "POST", `/api/tenants/${t.id}/pause`)).status).toBe(200);
    expect((await call(s, "GET", `/api/tenants/${t.id}/members`)).status).toBe(200);
  });

  it("unauthenticated → 401; session mutation without CSRF → 403", async () => {
    expect((await jsonRequest(app, "GET", "/api/tenants")).status).toBe(401);
    const s = await sessionFor({});
    const res = await jsonRequest(
      app,
      "POST",
      "/api/tenants",
      { name: "A", slug: "a" },
      {
        cookie: s.cookie,
      },
    );
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("csrf_required");
  });
});

describe("GET /api/tenants", () => {
  it("member sees only their tenants with counters and their role", async () => {
    const a = await createTenant({ name: "A" });
    await createTenant({ name: "B" });
    const s = await sessionFor({ tenantId: a.id, role: "admin" });
    await createApplication(a.id);
    await createResourceWithScopes(a.id, "https://api.a", ["read"]);

    const res = await call(s, "GET", "/api/tenants");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveLength(1);
    expect(body[0]).toMatchObject({
      id: a.id,
      name: "A",
      role: "admin",
      appCount: 1,
      resourceCount: 1,
      tokens24h: 0,
      issuer: `https://test.example.com/t/${a.slug}`,
    });
  });

  it("super-admin sees all tenants as owner", async () => {
    await createTenant({ name: "A" });
    await createTenant({ name: "B" });
    const s = await sessionFor({ superAdmin: true });
    const body = await (await call(s, "GET", "/api/tenants")).json();
    expect(body.map((t: { name: string; role: string }) => [t.name, t.role])).toEqual([
      ["A", "owner"],
      ["B", "owner"],
    ]);
  });
});

describe("POST /api/tenants", () => {
  it("201: creator becomes the only owner, one active signing key", async () => {
    const s = await sessionFor({});
    const res = await call(s, "POST", "/api/tenants", { name: "Acme", slug: "acme" });
    expect(res.status).toBe(201);
    const tenant = await res.json();
    expect(tenant).toMatchObject({ name: "Acme", slug: "acme", status: "active" });

    const members = await db
      .select()
      .from(tenantMembers)
      .where(eq(tenantMembers.tenantId, tenant.id));
    expect(members).toEqual([{ tenantId: tenant.id, adminUserId: s.user.id, role: "owner" }]);
    const keys = await db.select().from(signingKeys).where(eq(signingKeys.tenantId, tenant.id));
    expect(keys.map((k) => k.status)).toEqual(["active"]);
  });

  it("API key creation yields zero memberships", async () => {
    const res = await jsonRequest(
      apiKeyApp,
      "POST",
      "/api/tenants",
      { name: "Acme", slug: "acme" },
      { authorization: `Bearer ${API_KEY}` },
    );
    expect(res.status).toBe(201);
    const tenant = await res.json();
    expect(await countOf(tenantMembers, tenant.id)).toBe(0);
    expect(await countOf(signingKeys, tenant.id)).toBe(1);

    const list = await jsonRequest(apiKeyApp, "GET", "/api/tenants", undefined, {
      authorization: `Bearer ${API_KEY}`,
    });
    expect((await list.json())[0]).toMatchObject({ id: tenant.id, role: "owner" });
  });

  it("duplicate slug → 409 slug_exists; invalid body → 400", async () => {
    const s = await sessionFor({});
    await call(s, "POST", "/api/tenants", { name: "A", slug: "acme" });
    const dup = await call(s, "POST", "/api/tenants", { name: "B", slug: "acme" });
    expect(dup.status).toBe(409);
    expect((await dup.json()).error).toBe("slug_exists");
    const bad = await call(s, "POST", "/api/tenants", { name: "B", slug: "Not Valid" });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("validation_error");
  });
});

describe("tenant detail and mutations", () => {
  it("GET detail returns issuer URLs, stats and role", async () => {
    const t = await createTenant({ slug: "acme" });
    const s = await sessionFor({ tenantId: t.id, role: "auditor" });
    const body = await (await call(s, "GET", `/api/tenants/${t.id}`)).json();
    expect(body).toMatchObject({
      id: t.id,
      slug: "acme",
      issuer: "https://test.example.com/t/acme",
      discoveryUrl: "https://test.example.com/t/acme/.well-known/openid-configuration",
      jwksUrl: "https://test.example.com/t/acme/.well-known/jwks.json",
      role: "auditor",
    });
    expect(body.stats).toEqual({
      issued24h: 0,
      issuedPrev24h: 0,
      denied24h: 0,
      requests24h: 0,
      activeApps24h: 0,
      totalApps: 0,
    });
  });

  it("PATCH updates fields; invalid TTL → 400", async () => {
    const t = await createTenant();
    const s = await sessionFor({ tenantId: t.id, role: "admin" });
    const res = await call(s, "PATCH", `/api/tenants/${t.id}`, {
      defaultTokenTtlSeconds: 600,
      keyRotationDays: null,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ defaultTokenTtlSeconds: 600, keyRotationDays: null });
    const bad = await call(s, "PATCH", `/api/tenants/${t.id}`, { defaultTokenTtlSeconds: 5 });
    expect(bad.status).toBe(400);
  });

  it("owner: pause / resume / revoke-all-tokens return the updated tenant", async () => {
    const t = await createTenant();
    const s = await sessionFor({ tenantId: t.id, role: "owner" });
    expect((await (await call(s, "POST", `/api/tenants/${t.id}/pause`)).json()).status).toBe(
      "paused",
    );
    expect((await (await call(s, "POST", `/api/tenants/${t.id}/resume`)).json()).status).toBe(
      "active",
    );
    const revoked = await (await call(s, "POST", `/api/tenants/${t.id}/revoke-all-tokens`)).json();
    expect(revoked.tokensNotBefore).not.toBeNull();
  });

  it("DELETE: mismatched confirmSlug → 400; matching → 204 and children cascade", async () => {
    const t = await createTenant({ slug: "acme" });
    const s = await sessionFor({ tenantId: t.id, role: "owner" });
    await createApplication(t.id);
    await createResourceWithScopes(t.id, "https://api.acme", ["read", "write"]);
    await db.insert(signingKeys).values({
      tenantId: t.id,
      kid: "k_test",
      publicKeyPem: "x",
      privateKeyEnc: "x",
      status: "active",
    });
    expect(await countOf(applications, t.id)).toBe(1);
    expect(await countOf(scopes, t.id)).toBe(2);

    const bad = await call(s, "DELETE", `/api/tenants/${t.id}`, { confirmSlug: "nope" });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("confirm_slug_mismatch");
    const missing = await call(s, "DELETE", `/api/tenants/${t.id}`);
    expect(missing.status).toBe(400);

    const res = await call(s, "DELETE", `/api/tenants/${t.id}`, { confirmSlug: "acme" });
    expect(res.status).toBe(204);
    for (const table of [applications, scopes, signingKeys, tenantMembers]) {
      expect(await countOf(table, t.id)).toBe(0);
    }
    expect(await db.select().from(tenants)).toHaveLength(0);
  });
});
