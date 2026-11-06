// Integration test: real Postgres through the full app.
import { db, runMigrations, tokenEvents } from "@handsal/db";
import { Hono } from "hono";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type AppEnv, createApp } from "../../app.js";
import { errorHandler } from "../../middleware/error-handler.js";
import { tenantResolver } from "../../middleware/tenant-resolver.js";
import { ensureActiveKey, getJwks } from "../../services/signing-key.service.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../../test/factories.js";
import { formRequest } from "../../test/helpers.js";
import { verifyAccessToken } from "../../utils/jwt.js";
import { createTokenRoutes } from "./token.js";

const app = createApp({ readinessCheck: async () => {} });
const PAYMENTS = "https://api.acme.io/payments";

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

async function setup(over: { tenant?: Parameters<typeof createTenant>[0] } = {}) {
  const tenant = await createTenant(over.tenant);
  const { application, clientSecret } = await createApplication(tenant.id);
  const { resource, scopes } = await createResourceWithScopes(tenant.id, PAYMENTS, [
    "payments:write",
    "payments:read",
    "payments:refund",
  ]);
  // Grant write then read (not refund).
  await grant(tenant.id, application.id, [scopes[0].id, scopes[1].id]);
  const auth = { Authorization: basic(application.clientId, clientSecret) };
  return { tenant, application, clientSecret, resource, auth };
}

function tokenUrl(slug: string) {
  return `/t/${slug}/oauth/token`;
}

async function events() {
  return db.select().from(tokenEvents);
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("POST /t/:slug/oauth/token", () => {
  it("issues a verifiable ES256 JWT with all claims", async () => {
    const { tenant, application, auth, resource } = await setup();
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      { grant_type: "client_credentials", resource: PAYMENTS, scope: "payments:read" },
      auth,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Pragma")).toBe("no-cache");
    const body = await res.json();
    expect(body).toEqual({
      access_token: expect.any(String),
      token_type: "Bearer",
      expires_in: 3600,
      scope: "payments:read",
    });

    const issuer = `https://test.example.com/t/${tenant.slug}`;
    const { kid } = await ensureActiveKey(tenant.id);
    expect(decodeProtectedHeader(body.access_token)).toMatchObject({
      alg: "ES256",
      kid,
      typ: "at+jwt",
    });

    const payload = await verifyAccessToken(body.access_token, await getJwks(tenant.id), {
      issuer,
      audience: PAYMENTS,
    });
    expect(payload).toEqual({
      iss: issuer,
      sub: application.clientId,
      client_id: application.clientId,
      aud: PAYMENTS,
      scope: "payments:read",
      tenant: tenant.slug,
      client_kind: "service",
      jti: expect.any(String),
      iat: expect.any(Number),
      exp: (payload.iat as number) + 3600,
    });

    const [event] = await events();
    expect(event).toMatchObject({
      tenantId: tenant.id,
      applicationId: application.id,
      applicationClientId: application.clientId,
      resourceId: resource.id,
      audience: PAYMENTS,
      outcome: "issued",
      reason: null,
      scopes: ["payments:read"],
      jti: payload.jti,
    });
    expect(event.expiresAt?.getTime()).toBe((payload.exp as number) * 1000);
  });

  it("issues all granted scopes on the audience (ordered by name) when scope is omitted", async () => {
    const { tenant, auth } = await setup();
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      { grant_type: "client_credentials", resource: PAYMENTS },
      auth,
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.scope).toBe("payments:read payments:write");
    expect(decodeJwt(body.access_token).scope).toBe("payments:read payments:write");
  });

  it("accepts client_secret_post for a post-registered client", async () => {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "client_secret_post",
    });
    const { scopes } = await createResourceWithScopes(tenant.id, PAYMENTS, ["payments:read"]);
    await grant(tenant.id, application.id, [scopes[0].id]);
    const res = await formRequest(app, tokenUrl(tenant.slug), {
      grant_type: "client_credentials",
      resource: PAYMENTS,
      client_id: application.clientId,
      client_secret: clientSecret,
    });
    expect(res.status).toBe(200);
  });

  it("applies TTL precedence application > resource > tenant", async () => {
    const tenant = await createTenant({ defaultTokenTtlSeconds: 3600 });
    const { scopes } = await createResourceWithScopes(tenant.id, PAYMENTS, ["payments:read"], {
      tokenTtlSeconds: 1800,
    });
    const withAppTtl = await createApplication(tenant.id, { tokenTtlSeconds: 900 });
    const withoutAppTtl = await createApplication(tenant.id);
    await grant(tenant.id, withAppTtl.application.id, [scopes[0].id]);
    await grant(tenant.id, withoutAppTtl.application.id, [scopes[0].id]);

    const ttlFor = async (a: typeof withAppTtl) => {
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials", resource: PAYMENTS },
        { Authorization: basic(a.application.clientId, a.clientSecret) },
      );
      const { expires_in, access_token } = await res.json();
      const { iat, exp } = decodeJwt(access_token);
      expect(exp! - iat!).toBe(expires_in);
      return expires_in;
    };
    expect(await ttlFor(withAppTtl)).toBe(900);
    expect(await ttlFor(withoutAppTtl)).toBe(1800);

    const other = await createResourceWithScopes(tenant.id, "https://api.acme.io/other", [
      "x:read",
    ]);
    await grant(tenant.id, withoutAppTtl.application.id, [other.scopes[0].id]);
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      { grant_type: "client_credentials", resource: "https://api.acme.io/other" },
      { Authorization: basic(withoutAppTtl.application.clientId, withoutAppTtl.clientSecret) },
    );
    expect((await res.json()).expires_in).toBe(3600);
  });

  describe("failures record one denied token event", () => {
    async function expectDenied(
      res: Response,
      status: number,
      error: string,
      reason: string,
      extra: Record<string, unknown> = {},
    ) {
      expect(res.status).toBe(status);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      const body = await res.json();
      expect(body.error).toBe(error);
      const rows = await events();
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ outcome: "denied", reason, jti: null, ...extra });
      return body;
    }

    it("missing resource → invalid_target", async () => {
      const { tenant, auth, application } = await setup();
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials" },
        auth,
      );
      await expectDenied(res, 400, "invalid_target", "invalid_target", {
        applicationId: application.id,
        applicationClientId: application.clientId,
      });
    });

    it("foreign-tenant audience → invalid_target without leaking scopes", async () => {
      const { tenant, auth } = await setup();
      const other = await createTenant();
      const foreign = "https://api.other.io/secret";
      const otherApp = await createApplication(other.id);
      const { scopes } = await createResourceWithScopes(other.id, foreign, ["secret:read"]);
      await grant(other.id, otherApp.application.id, [scopes[0].id]);

      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials", resource: foreign },
        auth,
      );
      const body = await expectDenied(res, 400, "invalid_target", "invalid_target", {
        tenantId: tenant.id,
        audience: foreign,
      });
      expect(body.error_description).toBe("Unknown or unauthorized resource");
      expect(JSON.stringify(body)).not.toContain("secret:read");
    });

    it("scope outside the grant → invalid_scope without listing granted scopes", async () => {
      const { tenant, auth } = await setup();
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        {
          grant_type: "client_credentials",
          resource: PAYMENTS,
          scope: "payments:read payments:refund",
        },
        auth,
      );
      const body = await expectDenied(res, 400, "invalid_scope", "invalid_scope", {
        scopes: ["payments:read", "payments:refund"],
      });
      expect(body.error_description).not.toContain("payments:write");
    });

    it("paused tenant → 400 tenant paused", async () => {
      const { tenant, auth } = await setup({ tenant: { status: "paused" } });
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials", resource: PAYMENTS },
        auth,
      );
      const body = await expectDenied(res, 400, "invalid_request", "tenant_paused");
      expect(body.error_description).toBe("tenant paused");
    });

    it("wrong secret → 401 with WWW-Authenticate", async () => {
      const { tenant, application } = await setup();
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials", resource: PAYMENTS },
        { Authorization: basic(application.clientId, "hs_wrong") },
      );
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="handsal"');
      await expectDenied(res, 401, "invalid_client", "bad_secret", {
        applicationId: null,
        applicationClientId: application.clientId,
      });
    });

    it("unknown client → invalid_client, attempted client_id kept (truncated)", async () => {
      const { tenant } = await setup();
      const longId = `app_${"x".repeat(60)}`;
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials", resource: PAYMENTS },
        { Authorization: basic(longId, "hs_whatever") },
      );
      await expectDenied(res, 401, "invalid_client", "unknown_client", {
        applicationClientId: longId.slice(0, 32),
      });
    });

    it("missing credentials → invalid_client", async () => {
      const { tenant } = await setup();
      const res = await formRequest(app, tokenUrl(tenant.slug), {
        grant_type: "client_credentials",
        resource: PAYMENTS,
      });
      await expectDenied(res, 401, "invalid_client", "invalid_client");
    });

    it("basic-registered client sending the secret in the body → auth_method_mismatch", async () => {
      const { tenant, application, clientSecret } = await setup();
      const res = await formRequest(app, tokenUrl(tenant.slug), {
        grant_type: "client_credentials",
        resource: PAYMENTS,
        client_id: application.clientId,
        client_secret: clientSecret,
      });
      await expectDenied(res, 401, "invalid_client", "auth_method_mismatch");
    });

    it("unsupported grant_type", async () => {
      const { tenant, auth } = await setup();
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "password", resource: PAYMENTS },
        auth,
      );
      await expectDenied(res, 400, "unsupported_grant_type", "unsupported_grant_type");
    });

    it("JSON body → invalid_request", async () => {
      const { tenant, auth } = await setup();
      const res = await app.request(tokenUrl(tenant.slug), {
        method: "POST",
        headers: { "content-type": "application/json", ...auth },
        body: JSON.stringify({ grant_type: "client_credentials", resource: PAYMENTS }),
      });
      await expectDenied(res, 400, "invalid_request", "invalid_request");
    });
  });

  it("unknown tenant → 404 invalid_request, no event", async () => {
    const res = await formRequest(app, tokenUrl("no-such-tenant"), {
      grant_type: "client_credentials",
    });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({
      error: "invalid_request",
      error_description: "unknown tenant",
    });
    expect(await events()).toHaveLength(0);
  });

  it("rate-limits per client after RATE_LIMIT_TOKEN_CLIENT_MAX", async () => {
    const limited = new Hono<AppEnv>();
    const oauth = new Hono<AppEnv>();
    oauth.use("*", tenantResolver);
    oauth.route("/oauth/token", createTokenRoutes({ clientMax: 2 }));
    limited.route("/t/:slug", oauth);
    limited.onError(errorHandler);

    const { tenant, auth } = await setup();
    const fields = { grant_type: "client_credentials", resource: PAYMENTS };
    for (let i = 0; i < 2; i++) {
      expect((await formRequest(limited, tokenUrl(tenant.slug), fields, auth)).status).toBe(200);
    }
    const res = await formRequest(limited, tokenUrl(tenant.slug), fields, auth);
    expect(res.status).toBe(429);
    expect((await res.json()).error).toBe("too_many_requests");

    // Another client from the same IP has its own bucket.
    const other = await createApplication(tenant.id);
    const otherRes = await formRequest(limited, tokenUrl(tenant.slug), fields, {
      Authorization: basic(other.application.clientId, other.clientSecret),
    });
    expect(otherRes.status).not.toBe(429);
  });
});
