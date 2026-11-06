// Integration test: real Postgres through the full app.
import { applications, db, runMigrations, tenants } from "@handsal/db";
import { eq } from "drizzle-orm";
import { decodeJwt } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../app.js";
import { revokeAllApplicationTokens } from "../../services/application.service.js";
import { rotateKey } from "../../services/signing-key.service.js";
import { revokeAllTenantTokens } from "../../services/tenant.service.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../../test/factories.js";
import { formRequest } from "../../test/helpers.js";

const app = createApp({ readinessCheck: async () => {} });
const PAYMENTS = "https://api.acme.io/payments";

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

/** Tenant + app granted `payments:read` + a caller app (the resource server). */
async function setup(over: { tenant?: Parameters<typeof createTenant>[0] } = {}) {
  const tenant = await createTenant(over.tenant);
  const { application, clientSecret } = await createApplication(tenant.id);
  const { scopes } = await createResourceWithScopes(tenant.id, PAYMENTS, ["payments:read"]);
  await grant(tenant.id, application.id, [scopes[0].id]);
  const caller = await createApplication(tenant.id);
  return {
    tenant,
    application,
    auth: { Authorization: basic(application.clientId, clientSecret) },
    callerAuth: { Authorization: basic(caller.application.clientId, caller.clientSecret) },
  };
}

async function issue(slug: string, auth: Record<string, string>): Promise<string> {
  const res = await formRequest(
    app,
    `/t/${slug}/oauth/token`,
    { grant_type: "client_credentials", resource: PAYMENTS },
    auth,
  );
  expect(res.status).toBe(200);
  return ((await res.json()) as { access_token: string }).access_token;
}

async function introspect(slug: string, token: string, auth: Record<string, string>) {
  return formRequest(app, `/t/${slug}/oauth/introspect`, { token }, auth);
}

async function isActive(slug: string, token: string, auth: Record<string, string>) {
  const res = await introspect(slug, token, auth);
  expect(res.status).toBe(200);
  return ((await res.json()) as { active: boolean }).active;
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("POST /t/:slug/oauth/introspect", () => {
  it("returns active with all fields for an issued token", async () => {
    const { tenant, application, auth, callerAuth } = await setup();
    const token = await issue(tenant.slug, auth);
    const res = await introspect(tenant.slug, token, callerAuth);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const claims = decodeJwt(token);
    expect(await res.json()).toEqual({
      active: true,
      scope: "payments:read",
      client_id: application.clientId,
      token_type: "Bearer",
      exp: claims.exp,
      iat: claims.iat,
      sub: application.clientId,
      aud: PAYMENTS,
      iss: `https://test.example.com/t/${tenant.slug}`,
      jti: claims.jti,
      tenant: tenant.slug,
      client_kind: "service",
    });
  });

  it("accepts client_secret_post callers", async () => {
    const { tenant, auth } = await setup();
    const caller = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "client_secret_post",
    });
    const token = await issue(tenant.slug, auth);
    const res = await formRequest(app, `/t/${tenant.slug}/oauth/introspect`, {
      token,
      client_id: caller.application.clientId,
      client_secret: caller.clientSecret,
    });
    expect(res.status).toBe(200);
    expect((await res.json()).active).toBe(true);
  });

  it("returns { active: false } for a garbage token", async () => {
    const { tenant, callerAuth } = await setup();
    const res = await introspect(tenant.slug, "not.a.jwt", callerAuth);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ active: false });
  });

  it("treats a token of another tenant as inactive", async () => {
    const a = await setup();
    const b = await setup();
    const tokenB = await issue(b.tenant.slug, b.auth);
    expect(await isActive(a.tenant.slug, tokenB, a.callerAuth)).toBe(false);
  });

  it("is inactive after revocation by the owner", async () => {
    const { tenant, auth, callerAuth } = await setup();
    const token = await issue(tenant.slug, auth);
    const res = await formRequest(app, `/t/${tenant.slug}/oauth/revoke`, { token }, auth);
    expect(res.status).toBe(200);
    expect(await isActive(tenant.slug, token, callerAuth)).toBe(false);
  });

  it("stays active when another app tries to revoke it", async () => {
    const { tenant, auth, callerAuth } = await setup();
    const token = await issue(tenant.slug, auth);
    const res = await formRequest(app, `/t/${tenant.slug}/oauth/revoke`, { token }, callerAuth);
    expect(res.status).toBe(200);
    expect(await isActive(tenant.slug, token, callerAuth)).toBe(true);
  });

  it("honours application tokens_not_before (revoke-all)", async () => {
    const { tenant, application, auth, callerAuth } = await setup();
    const before = await issue(tenant.slug, auth);
    await revokeAllApplicationTokens(tenant.id, application.id);
    expect(await isActive(tenant.slug, before, callerAuth)).toBe(false);

    // Pin the mark around the issuance second instead of sleeping.
    const after = await issue(tenant.slug, auth);
    const issuedAt = (decodeJwt(after).iat as number) * 1000;
    const setMark = (ms: number) =>
      db
        .update(applications)
        .set({ tokensNotBefore: new Date(ms) })
        .where(eq(applications.id, application.id));
    await setMark(issuedAt - 1500);
    expect(await isActive(tenant.slug, after, callerAuth)).toBe(true);
    await setMark(issuedAt + 1500);
    expect(await isActive(tenant.slug, after, callerAuth)).toBe(false);
  });

  it("honours tenant tokens_not_before (revoke-all)", async () => {
    const { tenant, auth, callerAuth } = await setup();
    const before = await issue(tenant.slug, auth);
    await revokeAllTenantTokens(tenant.id);
    expect(await isActive(tenant.slug, before, callerAuth)).toBe(false);

    const after = await issue(tenant.slug, auth);
    const issuedAt = (decodeJwt(after).iat as number) * 1000;
    const setMark = (ms: number) =>
      db
        .update(tenants)
        .set({ tokensNotBefore: new Date(ms) })
        .where(eq(tenants.id, tenant.id));
    await setMark(issuedAt - 1500);
    expect(await isActive(tenant.slug, after, callerAuth)).toBe(true);
    await setMark(issuedAt + 1500);
    expect(await isActive(tenant.slug, after, callerAuth)).toBe(false);
  });

  it("is inactive when the application is disabled or deleted", async () => {
    const { tenant, application, auth, callerAuth } = await setup();
    const token = await issue(tenant.slug, auth);
    await db
      .update(applications)
      .set({ status: "disabled" })
      .where(eq(applications.id, application.id));
    expect(await isActive(tenant.slug, token, callerAuth)).toBe(false);
    await db.delete(applications).where(eq(applications.id, application.id));
    expect(await isActive(tenant.slug, token, callerAuth)).toBe(false);
  });

  it("is inactive when the tenant is paused", async () => {
    const { tenant, auth, callerAuth } = await setup();
    const token = await issue(tenant.slug, auth);
    await db.update(tenants).set({ status: "paused" }).where(eq(tenants.id, tenant.id));
    expect(await isActive(tenant.slug, token, callerAuth)).toBe(false);
  });

  it("keeps a token signed by a retiring key active", async () => {
    const { tenant, auth, callerAuth } = await setup();
    const token = await issue(tenant.slug, auth);
    await rotateKey(tenant.id, { graceSeconds: 3600 });
    expect(await isActive(tenant.slug, token, callerAuth)).toBe(true);
  });

  it("returns 404 when introspection is disabled, before client auth", async () => {
    const { tenant } = await setup({ tenant: { introspectionEnabled: false } });
    const res = await formRequest(app, `/t/${tenant.slug}/oauth/introspect`, { token: "x" });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({
      error: "invalid_request",
      error_description: "introspection disabled",
    });
  });

  it("returns 401 for unauthenticated or wrongly authenticated callers", async () => {
    const { tenant, application } = await setup();
    const none = await formRequest(app, `/t/${tenant.slug}/oauth/introspect`, { token: "x" });
    expect(none.status).toBe(401);
    expect((await none.json()).error).toBe("invalid_client");
    const bad = await introspect(tenant.slug, "x", {
      Authorization: basic(application.clientId, "hs_wrong"),
    });
    expect(bad.status).toBe(401);
  });

  it("returns 400 without a token parameter or with a non-form body", async () => {
    const { tenant, callerAuth } = await setup();
    const missing = await formRequest(app, `/t/${tenant.slug}/oauth/introspect`, {}, callerAuth);
    expect(missing.status).toBe(400);
    const json = await app.request(`/t/${tenant.slug}/oauth/introspect`, {
      method: "POST",
      headers: { "content-type": "application/json", ...callerAuth },
      body: JSON.stringify({ token: "x" }),
    });
    expect(json.status).toBe(400);
  });
});
