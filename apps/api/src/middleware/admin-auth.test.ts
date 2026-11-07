import crypto from "node:crypto";
import { adminUsers, db, pool, runMigrations } from "@handsal/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { env } from "../env.js";
import { createAdminUser, truncateAll } from "../test/factories.js";
import { deriveKey } from "../utils/crypto.js";
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

function probeApp() {
  const app = new Hono<AdminEnv>();
  app.use("*", createAdminAuth(), csrfProtection);
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

/** Sign a payload with the session key, so tests can forge a pre-`sv` cookie the HMAC would accept. */
function signSessionPayload(payload: Record<string, unknown>): string {
  const key = deriveKey(env.KEY_ENCRYPTION_SECRET, "admin-session");
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", key).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

describe("session token", () => {
  it("round-trips and expires after 12 h", () => {
    const now = Date.now();
    const token = createSessionToken("user-1", now);
    expect(verifySessionToken(token, now)).toMatchObject({ sub: "user-1", sv: 0 });
    expect(verifySessionToken(token, now + (SESSION_TTL_SECONDS - 1) * 1000)).not.toBeNull();
    expect(verifySessionToken(token, now + (SESSION_TTL_SECONDS + 1) * 1000)).toBeNull();
    expect(verifySessionToken(createSessionToken("user-1", now, 3), now)?.sv).toBe(3);
  });

  it("rejects garbage and unsigned tokens", () => {
    expect(verifySessionToken("")).toBeNull();
    expect(verifySessionToken("a.b.c")).toBeNull();
    const payload = Buffer.from(JSON.stringify({ sub: "u", iat: 0, exp: 9e9 })).toString(
      "base64url",
    );
    expect(verifySessionToken(`${payload}.`)).toBeNull();
  });

  it("rejects a signed token with no sv", () => {
    const now = Math.floor(Date.now() / 1000);
    const base = { sub: "user-1", iat: now, exp: now + 60 };
    expect(verifySessionToken(signSessionPayload({ ...base, sv: 0 }))?.sv).toBe(0);
    expect(verifySessionToken(signSessionPayload(base))).toBeNull();
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

  it("rejects a cookie whose session version does not match the user", async () => {
    const { user } = await createAdminUser();
    await db.update(adminUsers).set({ sessionVersion: 1 }).where(eq(adminUsers.id, user.id));
    const token = createSessionToken(user.id, Date.now(), 0);
    const res = await probeApp().request("/x", {
      headers: { cookie: `${SESSION_COOKIE}=${token}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({
      error: "unauthenticated",
      error_description: "Authentication required",
    });
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

  it("a bearer token is not a management credential", async () => {
    const res = await probeApp().request("/x", {
      headers: { authorization: `Bearer ${"k".repeat(48)}` },
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
