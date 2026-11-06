import { adminUsers, db, pool, runMigrations } from "@handsal/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import { addMember, createAdminUser, createTenant, truncateAll } from "../../test/factories.js";
import { jsonRequest, loginAs } from "../../test/helpers.js";
import { loginRateLimitStore } from "./auth.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
  await loginRateLimitStore.clear();
});

afterAll(async () => {
  await pool.end();
});

const login = (email: string, password: string) =>
  jsonRequest(app, "POST", "/api/auth/login", { email, password });

describe("POST /api/auth/login", () => {
  it("returns the user + csrfToken and sets an HttpOnly SameSite=Strict cookie", async () => {
    const { user, password } = await createAdminUser({ name: "Ada" });
    const res = await login(user.email, password);

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.user).toEqual({ id: user.id, email: user.email, name: "Ada", isSuperAdmin: false });
    expect(typeof body.csrfToken).toBe("string");

    const cookie = res.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/^handsal_session=/);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Path=/");
    expect(cookie).not.toContain("Secure"); // NODE_ENV=test

    const [row] = await db.select().from(adminUsers).where(eq(adminUsers.id, user.id));
    expect(row.lastLoginAt).toBeInstanceOf(Date);
  });

  it.each([
    ["wrong password", (email: string) => login(email, "not-the-password")],
    ["unknown email", () => login("nobody@example.com", "whatever-password")],
  ])("%s → 401 invalid_credentials", async (_label, attempt) => {
    const { user } = await createAdminUser();
    const res = await attempt(user.email);
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("invalid_credentials");
  });

  it("inactive user → 401 invalid_credentials", async () => {
    const { user, password } = await createAdminUser();
    await db.update(adminUsers).set({ isActive: false }).where(eq(adminUsers.id, user.id));
    const res = await login(user.email, password);
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("invalid_credentials");
  });

  it("invalid body → 400 validation_error", async () => {
    const res = await jsonRequest(app, "POST", "/api/auth/login", { email: "nope" });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("validation_error");
  });

  it("6th attempt in the window → 429", async () => {
    for (let i = 0; i < 5; i++) {
      expect((await login("x@example.com", "wrong-password")).status).toBe(401);
    }
    const res = await login("x@example.com", "wrong-password");
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBeTruthy();
  });
});

describe("session cycle", () => {
  it("login → me → logout", async () => {
    const { user, password } = await createAdminUser();
    const tenant = await createTenant({ name: "Acme" });
    await addMember(tenant.id, user.id, "admin");
    const { cookie, csrf } = await loginAs(app, user.email, password);

    const me = await jsonRequest(app, "GET", "/api/auth/me", undefined, { cookie });
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({
      user: { id: user.id, email: user.email, name: user.name, isSuperAdmin: false },
      tenants: [
        {
          id: tenant.id,
          name: "Acme",
          slug: tenant.slug,
          issuer: `https://test.example.com/t/${tenant.slug}`,
          role: "admin",
        },
      ],
      csrfToken: csrf,
    });

    const out = await jsonRequest(app, "POST", "/api/auth/logout", undefined, { cookie });
    expect(out.status).toBe(204);
    const cleared = out.headers.get("set-cookie") ?? "";
    expect(cleared).toMatch(/^handsal_session=;/);
    expect(cleared).toContain("Max-Age=0");
  });

  it("super-admin /me lists every tenant as owner", async () => {
    const { user, password } = await createAdminUser({ isSuperAdmin: true });
    const a = await createTenant({ name: "A" });
    const b = await createTenant({ name: "B" });
    const { cookie } = await loginAs(app, user.email, password);

    const body = await (
      await jsonRequest(app, "GET", "/api/auth/me", undefined, { cookie })
    ).json();
    expect(body.tenants).toEqual([
      {
        id: a.id,
        name: "A",
        slug: a.slug,
        issuer: `https://test.example.com/t/${a.slug}`,
        role: "owner",
      },
      {
        id: b.id,
        name: "B",
        slug: b.slug,
        issuer: `https://test.example.com/t/${b.slug}`,
        role: "owner",
      },
    ]);
  });

  it("no cookie → 401 unauthenticated", async () => {
    const res = await jsonRequest(app, "GET", "/api/auth/me");
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("unauthenticated");
  });

  it("tampered cookie → 401", async () => {
    const { user, password } = await createAdminUser();
    const { cookie } = await loginAs(app, user.email, password);
    const [name, value] = cookie.split("=");
    const [payload, sig] = value.split(".");
    const forged = Buffer.from(
      JSON.stringify({ ...JSON.parse(Buffer.from(payload, "base64url").toString()), sub: "x" }),
    ).toString("base64url");

    for (const bad of [`${name}=${forged}.${sig}`, `${name}=${payload}.${sig.slice(0, -2)}AA`]) {
      const res = await jsonRequest(app, "GET", "/api/auth/me", undefined, { cookie: bad });
      expect(res.status).toBe(401);
    }
  });

  it("session of a deactivated user → 401", async () => {
    const { user, password } = await createAdminUser();
    const { cookie } = await loginAs(app, user.email, password);
    await db.update(adminUsers).set({ isActive: false }).where(eq(adminUsers.id, user.id));
    const res = await jsonRequest(app, "GET", "/api/auth/me", undefined, { cookie });
    expect(res.status).toBe(401);
  });
});

describe("CSRF", () => {
  it("mutating call without X-CSRF-Token → 403 csrf_required; with it passes CSRF", async () => {
    const { user, password } = await createAdminUser();
    const { cookie, csrf } = await loginAs(app, user.email, password);

    const missing = await jsonRequest(app, "POST", "/api/auth/me", {}, { cookie });
    expect(missing.status).toBe(403);
    expect((await missing.json()).error).toBe("csrf_required");

    const wrong = await jsonRequest(
      app,
      "POST",
      "/api/auth/me",
      {},
      { cookie, "x-csrf-token": "x" },
    );
    expect(wrong.status).toBe(403);

    // Valid token gets past CSRF to routing (no POST /me route → 404).
    const ok = await jsonRequest(app, "POST", "/api/auth/me", {}, { cookie, "x-csrf-token": csrf });
    expect(ok.status).toBe(404);
  });

  it("CSRF token of another session is rejected", async () => {
    const a = await createAdminUser();
    const b = await createAdminUser();
    const sa = await loginAs(app, a.user.email, a.password);
    const sb = await loginAs(app, b.user.email, b.password);
    const res = await jsonRequest(app, "DELETE", "/api/auth/me", undefined, {
      cookie: sa.cookie,
      "x-csrf-token": sb.csrf,
    });
    expect(res.status).toBe(403);
  });
});
