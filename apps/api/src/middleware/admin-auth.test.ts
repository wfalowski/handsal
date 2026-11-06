import { pool, runMigrations } from "@handsal/db";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createAdminUser, truncateAll } from "../test/factories.js";
import {
  type AdminEnv,
  createAdminAuth,
  createSessionToken,
  csrfProtection,
  csrfTokenFor,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  verifySessionToken,
} from "./admin-auth.js";
import { errorHandler } from "./error-handler.js";

const API_KEY = "k".repeat(40);

function probeApp(apiKey?: string) {
  const app = new Hono<AdminEnv>();
  app.use("*", createAdminAuth({ apiKey }), csrfProtection);
  app.all("/x", (c) => c.json(c.var.actor));
  app.onError(errorHandler);
  return app;
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

describe("session token", () => {
  it("round-trips and expires after 12 h", () => {
    const now = Date.now();
    const token = createSessionToken("user-1", now);
    expect(verifySessionToken(token, now)?.sub).toBe("user-1");
    expect(verifySessionToken(token, now + (SESSION_TTL_SECONDS - 1) * 1000)).not.toBeNull();
    expect(verifySessionToken(token, now + (SESSION_TTL_SECONDS + 1) * 1000)).toBeNull();
  });

  it("rejects garbage and unsigned tokens", () => {
    expect(verifySessionToken("")).toBeNull();
    expect(verifySessionToken("a.b.c")).toBeNull();
    const payload = Buffer.from(JSON.stringify({ sub: "u", iat: 0, exp: 9e9 })).toString(
      "base64url",
    );
    expect(verifySessionToken(`${payload}.`)).toBeNull();
  });
});

describe("adminAuth", () => {
  it("rejects an expired session cookie", async () => {
    const { user } = await createAdminUser();
    const token = createSessionToken(user.id, Date.now() - (SESSION_TTL_SECONDS + 5) * 1000);
    const res = await probeApp().request("/x", {
      headers: { cookie: `${SESSION_COOKIE}=${token}` },
    });
    expect(res.status).toBe(401);
  });

  it("accepts a valid session cookie as a user actor", async () => {
    const { user } = await createAdminUser({ isSuperAdmin: true });
    const token = createSessionToken(user.id);
    const res = await probeApp().request("/x", {
      headers: { cookie: `${SESSION_COOKIE}=${token}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      kind: "user",
      userId: user.id,
      email: user.email,
      name: user.name,
      isSuperAdmin: true,
    });
  });

  it("API key passes as super-admin and skips CSRF", async () => {
    const res = await probeApp(API_KEY).request("/x", {
      method: "POST",
      headers: { authorization: `Bearer ${API_KEY}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ kind: "api-key", isSuperAdmin: true });
  });

  it("wrong API key → 401", async () => {
    for (const key of ["k".repeat(39), "x".repeat(40), ""]) {
      const res = await probeApp(API_KEY).request("/x", {
        headers: { authorization: `Bearer ${key}` },
      });
      expect(res.status).toBe(401);
    }
  });

  it("bearer path is disabled when no API key is configured", async () => {
    const res = await probeApp(undefined).request("/x", {
      headers: { authorization: `Bearer ${API_KEY}` },
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("unauthenticated");
  });

  it("session actor needs the matching CSRF token on mutations", async () => {
    const { user } = await createAdminUser();
    const token = createSessionToken(user.id);
    const cookie = `${SESSION_COOKIE}=${token}`;
    const app = probeApp();

    const missing = await app.request("/x", { method: "PATCH", headers: { cookie } });
    expect(missing.status).toBe(403);
    expect((await missing.json()).error).toBe("csrf_required");

    const ok = await app.request("/x", {
      method: "PATCH",
      headers: { cookie, "x-csrf-token": csrfTokenFor(token) },
    });
    expect(ok.status).toBe(200);
  });
});
