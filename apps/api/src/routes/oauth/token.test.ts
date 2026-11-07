// Integration test: real Postgres through the full app.
import {
  approvalRequests,
  db,
  runMigrations,
  scopes as scopesTable,
  tokenEvents,
} from "@handsal/db";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// No socket in app.request. Throw unless a test installs a trusted peer, so
// forwarding headers stay ignored the way they are for a direct caller.
const { mockGetConnInfo } = vi.hoisted(() => ({
  mockGetConnInfo: vi.fn(() => {
    throw new Error("no conninfo");
  }),
}));
vi.mock("@hono/node-server/conninfo", () => ({ getConnInfo: mockGetConnInfo }));

import { type AppEnv, createApp } from "../../app.js";
import { env } from "../../env.js";
import { errorHandler } from "../../middleware/error-handler.js";
import { tenantResolver } from "../../middleware/tenant-resolver.js";
import { ensureActiveKey, getJwks } from "../../services/signing-key.service.js";
import {
  createApplication,
  createApplicationKey,
  createApprovalRule,
  createResourceWithScopes,
  createTenant,
  grant,
  signClientAssertion,
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

  it("repeated parameters → 400 (invalid_target for resource, invalid_request otherwise)", async () => {
    const { tenant, auth } = await setup();
    const post = (body: string) =>
      app.request(tokenUrl(tenant.slug), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", ...auth },
        body,
      });
    const twoResources = await post(
      `grant_type=client_credentials&resource=${encodeURIComponent(PAYMENTS)}&resource=https%3A%2F%2Fb.example`,
    );
    expect(twoResources.status).toBe(400);
    expect((await twoResources.json()).error).toBe("invalid_target");
    const twoScopes = await post(
      `grant_type=client_credentials&resource=${encodeURIComponent(PAYMENTS)}&scope=a&scope=b`,
    );
    expect(twoScopes.status).toBe(400);
    expect((await twoScopes.json()).error).toBe("invalid_request");
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

    it("over-long resource → invalid_target", async () => {
      const { tenant, auth } = await setup();
      const res = await formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials", resource: `https://a.example/${"x".repeat(600)}` },
        auth,
      );
      const body = await expectDenied(res, 400, "invalid_target", "invalid_target");
      expect(body.error_description).toBe("resource is invalid");
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

    // The same client_id from another source IP is not locked out by the first source.
    const prevTrustProxy = env.TRUST_PROXY;
    env.TRUST_PROXY = "true";
    mockGetConnInfo.mockReturnValue({ remote: { address: "127.0.0.1" } });
    try {
      const fromA = { ...auth, "X-Forwarded-For": "203.0.113.1" };
      const fromB = { ...auth, "X-Forwarded-For": "203.0.113.2" };
      for (let i = 0; i < 2; i++) {
        expect((await formRequest(limited, tokenUrl(tenant.slug), fields, fromA)).status).toBe(200);
      }
      expect((await formRequest(limited, tokenUrl(tenant.slug), fields, fromA)).status).toBe(429);
      expect((await formRequest(limited, tokenUrl(tenant.slug), fields, fromB)).status).toBe(200);
    } finally {
      env.TRUST_PROXY = prevTrustProxy;
      mockGetConnInfo.mockImplementation(() => {
        throw new Error("no conninfo");
      });
    }
  });
});

describe("private_key_jwt client authentication", () => {
  const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  async function pkSetup() {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "private_key_jwt",
    });
    const { scopes } = await createResourceWithScopes(tenant.id, PAYMENTS, ["payments:read"]);
    await grant(tenant.id, application.id, [scopes[0].id]);
    const { key, privateKey } = await createApplicationKey(tenant.id, application.id);
    const sign = (claims: Record<string, unknown> = {}) =>
      signClientAssertion(privateKey, {
        clientId: application.clientId,
        kid: key.kid,
        tenantSlug: tenant.slug,
        claims,
      });
    const fields = async (over: Record<string, string> = {}) => ({
      grant_type: "client_credentials",
      resource: PAYMENTS,
      client_assertion_type: JWT_BEARER,
      client_assertion: await sign(),
      ...over,
    });
    return { tenant, application, clientSecret, sign, fields };
  }

  async function expectInvalidClient(res: Response, reason: string) {
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="handsal"');
    expect(await res.json()).toEqual({
      error: "invalid_client",
      error_description: "Invalid client credentials",
    });
    const rows = await events();
    expect(rows.at(-1)).toMatchObject({ outcome: "denied", reason });
  }

  it("issues a token for an assertion signed by a registered key", async () => {
    const { tenant, application, fields } = await pkSetup();
    const res = await formRequest(app, tokenUrl(tenant.slug), await fields());
    expect(res.status).toBe(200);
    const { access_token } = await res.json();
    expect(decodeJwt(access_token).client_id).toBe(application.clientId);
    const [event] = await events();
    expect(event).toMatchObject({ outcome: "issued", applicationClientId: application.clientId });
  });

  it("aud = issuer → 401 bad_assertion, recorded under the assertion's client id", async () => {
    const { tenant, application, sign, fields } = await pkSetup();
    const assertion = await sign({ aud: `https://test.example.com/t/${tenant.slug}` });
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      await fields({ client_assertion: assertion }),
    );
    await expectInvalidClient(res, "bad_assertion");
    expect((await events())[0].applicationClientId).toBe(application.clientId);
  });

  it("oversized assertion → 400 invalid_request before auth, its jti stays unused", async () => {
    const { tenant, sign, fields } = await pkSetup();
    const jti = "fixed-jti";
    const big = await sign({ jti, pad: "x".repeat(4096) });
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      await fields({ client_assertion: big }),
    );
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_request");
    const ok = await formRequest(
      app,
      tokenUrl(tenant.slug),
      await fields({ client_assertion: await sign({ jti }) }),
    );
    expect(ok.status).toBe(200);
  });

  it("the same assertion twice → 200 then 401 assertion_replayed", async () => {
    const { tenant, fields } = await pkSetup();
    const body = await fields();
    expect((await formRequest(app, tokenUrl(tenant.slug), body)).status).toBe(200);
    await expectInvalidClient(
      await formRequest(app, tokenUrl(tenant.slug), body),
      "assertion_replayed",
    );
  });

  it("Basic credentials for a private_key_jwt client → 401 auth_method_mismatch", async () => {
    const { tenant, application, clientSecret } = await pkSetup();
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      { grant_type: "client_credentials", resource: PAYMENTS },
      { Authorization: basic(application.clientId, clientSecret) },
    );
    await expectInvalidClient(res, "auth_method_mismatch");
  });

  it("client_id different from iss → 401", async () => {
    const { tenant, fields } = await pkSetup();
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      await fields({ client_id: "someone-else" }),
    );
    await expectInvalidClient(res, "bad_assertion");
  });

  it("malformed assertion parameters → 400 invalid_request", async () => {
    const { tenant, application, clientSecret, fields } = await pkSetup();
    const cases: [Record<string, string>, Record<string, string>][] = [
      [await fields({ client_secret: clientSecret }), {}],
      [await fields(), { Authorization: basic(application.clientId, clientSecret) }],
      [await fields({ client_assertion_type: "urn:example:other" }), {}],
      [{ grant_type: "client_credentials", resource: PAYMENTS, client_assertion: "x" }, {}],
    ];
    for (const [body, headers] of cases) {
      const res = await formRequest(app, tokenUrl(tenant.slug), body, headers);
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_request");
    }
  });

  it("a private_key_jwt client introspects and revokes its own token", async () => {
    const { tenant, fields, sign } = await pkSetup();
    const issued = await formRequest(app, tokenUrl(tenant.slug), await fields());
    const { access_token } = await issued.json();
    const authFields = async () => ({
      client_assertion_type: JWT_BEARER,
      client_assertion: await sign(),
      token: access_token,
    });

    const introspected = await formRequest(
      app,
      `/t/${tenant.slug}/oauth/introspect`,
      await authFields(),
    );
    expect(introspected.status).toBe(200);
    expect((await introspected.json()).active).toBe(true);

    const revoked = await formRequest(app, `/t/${tenant.slug}/oauth/revoke`, await authFields());
    expect(revoked.status).toBe(200);
    const after = await formRequest(app, `/t/${tenant.slug}/oauth/introspect`, await authFields());
    expect((await after.json()).active).toBe(false);
  });
});

describe("task_id passthrough", () => {
  it("claim present when sent, absent otherwise; stored on the event", async () => {
    const { tenant, auth } = await setup();
    const fields = { grant_type: "client_credentials", resource: PAYMENTS };
    const withTask = await formRequest(
      app,
      tokenUrl(tenant.slug),
      { ...fields, task_id: "run-42" },
      auth,
    );
    expect(decodeJwt((await withTask.json()).access_token).task_id).toBe("run-42");
    const without = await formRequest(app, tokenUrl(tenant.slug), fields, auth);
    expect(decodeJwt((await without.json()).access_token)).not.toHaveProperty("task_id");
    const rows = await db.select().from(tokenEvents).orderBy(tokenEvents.id);
    expect(rows.map((r) => r.taskId)).toEqual(["run-42", null]);
  });

  it("task_id over 128 chars → invalid_request; a denied event keeps a truncated task_id", async () => {
    const { tenant, auth } = await setup();
    const long = "t".repeat(129);
    const res = await formRequest(
      app,
      tokenUrl(tenant.slug),
      { grant_type: "client_credentials", resource: PAYMENTS, task_id: long },
      auth,
    );
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_request");
    const denied = await formRequest(
      app,
      tokenUrl(tenant.slug),
      { grant_type: "client_credentials", resource: PAYMENTS, scope: "nope", task_id: "run-1" },
      auth,
    );
    expect(denied.status).toBe(400);
    const rows = await db.select().from(tokenEvents).orderBy(tokenEvents.id);
    expect(rows.map((r) => [r.outcome, r.taskId])).toEqual([
      ["denied", long.slice(0, 128)],
      ["denied", "run-1"],
    ]);
  });
});

describe("approval grant", () => {
  const APPROVAL = "urn:handsal:params:grant-type:approval";

  /** Agent granted payments:read (auto) and payments:write (approval). */
  async function agentSetup() {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id, { kind: "agent" });
    const { scopes } = await createResourceWithScopes(tenant.id, PAYMENTS, [
      "payments:read",
      "payments:write",
    ]);
    await db
      .update(scopesTable)
      .set({ agentPolicy: "approval" })
      .where(eq(scopesTable.id, scopes[1].id));
    await grant(
      tenant.id,
      application.id,
      scopes.map((s) => s.id),
    );
    const auth = { Authorization: basic(application.clientId, clientSecret) };
    const request = (fields: Record<string, string>) =>
      formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: "client_credentials", resource: PAYMENTS, ...fields },
        auth,
      );
    const poll = (approvalId: string, headers = auth) =>
      formRequest(
        app,
        tokenUrl(tenant.slug),
        { grant_type: APPROVAL, approval_id: approvalId },
        headers,
      );
    return { tenant, application, auth, request, poll };
  }

  async function approve(id: string) {
    await db
      .update(approvalRequests)
      .set({ status: "approved", decidedAt: new Date() })
      .where(eq(approvalRequests.id, id));
  }

  it("pending response carries approval_id and interval, with no-store headers", async () => {
    const s = await agentSetup();
    const res = await s.request({
      scope: "payments:read payments:write",
      task_id: "run-5",
      actor_hint: "alice@example.com",
      justification: "nightly refunds",
    });
    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Pragma")).toBe("no-cache");
    const body = await res.json();
    expect(body).toEqual({
      error: "authorization_pending",
      error_description: expect.any(String),
      approval_id: expect.any(String),
      interval: 5,
    });
    const [row] = await db.select().from(approvalRequests);
    expect(row).toMatchObject({
      id: body.approval_id,
      scopes: ["payments:read", "payments:write"],
      taskId: "run-5",
      actorHint: "alice@example.com",
      justification: "nightly refunds",
    });
    // One pending event, no denied event from the catch block.
    expect((await events()).map((e) => e.outcome)).toEqual(["pending"]);

    const polled = await s.poll(body.approval_id);
    expect(polled.status).toBe(400);
    expect(await polled.json()).toMatchObject({
      error: "authorization_pending",
      approval_id: body.approval_id,
      interval: 5,
    });
  });

  it("approved → one 300 s token with the row's scopes and task_id; second poll invalid_grant", async () => {
    const s = await agentSetup();
    const { approval_id } = await (
      await s.request({ scope: "payments:write", task_id: "run-6" })
    ).json();
    await approve(approval_id);

    const ok = await s.poll(approval_id);
    expect(ok.status).toBe(200);
    expect(ok.headers.get("Cache-Control")).toBe("no-store");
    const body = await ok.json();
    expect(body).toMatchObject({ token_type: "Bearer", expires_in: 300, scope: "payments:write" });
    expect(decodeJwt(body.access_token)).toMatchObject({
      aud: PAYMENTS,
      scope: "payments:write",
      task_id: "run-6",
      client_kind: "agent",
    });

    const again = await s.poll(approval_id);
    expect(again.status).toBe(400);
    expect((await again.json()).error).toBe("invalid_grant");
  });

  it("concurrent double-poll issues exactly one token", async () => {
    const s = await agentSetup();
    const { approval_id } = await (await s.request({ scope: "payments:write" })).json();
    await approve(approval_id);
    const results = await Promise.all([s.poll(approval_id), s.poll(approval_id)]);
    const statuses = results.map((r) => r.status).sort();
    // The loser is invalid_grant, or 503 when the per-source hash lane is already busy.
    expect(statuses[0]).toBe(200);
    expect([400, 503]).toContain(statuses[1]);
    const issued = (await events()).filter((e) => e.outcome === "issued");
    expect(issued).toHaveLength(1);
  });

  it("denied → access_denied; expired → expired_token", async () => {
    const s = await agentSetup();
    const { approval_id: deniedId } = await (
      await s.request({ scope: "payments:write", task_id: "a" })
    ).json();
    await db
      .update(approvalRequests)
      .set({ status: "denied" })
      .where(eq(approvalRequests.id, deniedId));
    expect((await (await s.poll(deniedId)).json()).error).toBe("access_denied");

    const { approval_id: expiredId } = await (
      await s.request({ scope: "payments:write", task_id: "b" })
    ).json();
    await db
      .update(approvalRequests)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(approvalRequests.id, expiredId));
    expect((await (await s.poll(expiredId)).json()).error).toBe("expired_token");
  });

  it("approval_id from another tenant or another application → invalid_grant", async () => {
    const s = await agentSetup();
    const { approval_id } = await (await s.request({ scope: "payments:write" })).json();
    await approve(approval_id);

    const otherTenant = await agentSetup();
    const cross = await otherTenant.poll(approval_id);
    expect(cross.status).toBe(400);
    expect((await cross.json()).error).toBe("invalid_grant");

    const sibling = await createApplication(s.tenant.id, { kind: "agent" });
    const siblingAuth = {
      Authorization: basic(sibling.application.clientId, sibling.clientSecret),
    };
    const stolen = await s.poll(approval_id, siblingAuth);
    expect((await stolen.json()).error).toBe("invalid_grant");

    // Still redeemable by its owner.
    expect((await s.poll(approval_id)).status).toBe(200);
  });

  it("poll requires client auth and a valid approval_id", async () => {
    const s = await agentSetup();
    const noAuth = await formRequest(app, tokenUrl(s.tenant.slug), {
      grant_type: APPROVAL,
      approval_id: "00000000-0000-4000-8000-000000000000",
    });
    expect(noAuth.status).toBe(401);
    const bad = await s.poll("not-a-uuid");
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("invalid_request");
  });

  it("auto-only agent requests issue directly", async () => {
    const s = await agentSetup();
    const auto = await s.request({ scope: "payments:read" });
    expect(auto.status).toBe(200);
    expect(await db.select().from(approvalRequests)).toHaveLength(0);
  });

  it("poll with resource, scope or task_id → invalid_request", async () => {
    const s = await agentSetup();
    const { approval_id } = await (await s.request({ scope: "payments:write" })).json();
    await approve(approval_id);
    const extras: Record<string, string>[] = [
      { resource: PAYMENTS },
      { scope: "payments:write" },
      { task_id: "t" },
    ];
    for (const extra of extras) {
      const res = await formRequest(
        app,
        tokenUrl(s.tenant.slug),
        { grant_type: APPROVAL, approval_id, ...extra },
        s.auth,
      );
      expect(await res.json()).toEqual({
        error: "invalid_request",
        error_description: "resource, scope and task_id are taken from the approval",
      });
    }
    // Rejected before redemption: the approval is still usable.
    expect((await s.poll(approval_id)).status).toBe(200);
  });

  it("a denied poll records the row's audience and scopes", async () => {
    const s = await agentSetup();
    const { approval_id } = await (await s.request({ scope: "payments:write" })).json();
    await db
      .update(approvalRequests)
      .set({ status: "denied" })
      .where(eq(approvalRequests.id, approval_id));
    await s.poll(approval_id);
    const [denied] = (await events()).filter((e) => e.outcome === "denied");
    expect(denied).toMatchObject({
      reason: "approval_denied",
      audience: PAYMENTS,
      scopes: ["payments:write"],
    });
  });

  it("a rule-approved request answers interval 0", async () => {
    const s = await agentSetup();
    const [write] = await db
      .select()
      .from(scopesTable)
      .where(and(eq(scopesTable.tenantId, s.tenant.id), eq(scopesTable.name, "payments:write")));
    await createApprovalRule(s.tenant.id, write.id);
    const body = await (await s.request({ scope: "payments:write" })).json();
    expect(body).toMatchObject({ error: "authorization_pending", interval: 0 });
    expect((await s.poll(body.approval_id)).status).toBe(200);
  });
});

describe("token exchange grant", () => {
  const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
  const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

  async function exchangeSetup() {
    const s = await setup();
    const issued = await formRequest(
      app,
      tokenUrl(s.tenant.slug),
      { grant_type: "client_credentials", resource: PAYMENTS, scope: "payments:read" },
      s.auth,
    );
    const subject = (await issued.json()).access_token as string;
    const agent = await createApplication(s.tenant.id, { kind: "agent", mayActFor: ["services"] });
    const [read] = await db.select().from(scopesTable).where(eq(scopesTable.name, "payments:read"));
    await grant(s.tenant.id, agent.application.id, [read.id]);
    const agentAuth = { Authorization: basic(agent.application.clientId, agent.clientSecret) };
    const exchange = (fields: Record<string, string> = {}) =>
      formRequest(
        app,
        tokenUrl(s.tenant.slug),
        {
          grant_type: EXCHANGE,
          subject_token: subject,
          subject_token_type: ACCESS_TOKEN_TYPE,
          resource: PAYMENTS,
          ...fields,
        },
        agentAuth,
      );
    return { ...s, agent: agent.application, exchange };
  }

  it("response carries issued_token_type and a delegated token", async () => {
    const s = await exchangeSetup();
    const res = await s.exchange({ task_id: "task-7" });
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json();
    expect(body).toMatchObject({
      access_token: expect.any(String),
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: "Bearer",
      scope: "payments:read",
    });
    // Capped by the subject token, which is a second or two under its original hour.
    expect(body.expires_in).toBeLessThanOrEqual(3600);
    expect(body.expires_in).toBeGreaterThan(3500);
    expect(decodeJwt(body.access_token)).toMatchObject({
      sub: s.application.clientId,
      act: { sub: s.agent.clientId },
      client_id: s.agent.clientId,
      task_id: "task-7",
    });
  });

  it("actor_token present → invalid_request", async () => {
    const s = await exchangeSetup();
    const res = await s.exchange({ actor_token: "x", actor_token_type: ACCESS_TOKEN_TYPE });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "invalid_request",
      error_description: "actor_token is not supported",
    });
    const noResource = await s.exchange({ actor_token: "x", resource: "" });
    expect((await noResource.json()).error).toBe("invalid_request");
  });

  it("unknown subject_token_type → invalid_request", async () => {
    const s = await exchangeSetup();
    const res = await s.exchange({ subject_token_type: "urn:ietf:params:oauth:token-type:saml2" });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_request");
  });

  it("missing resource → invalid_target; garbage subject → invalid_grant (recorded denied)", async () => {
    const s = await exchangeSetup();
    expect((await (await s.exchange({ resource: "" })).json()).error).toBe("invalid_target");
    const bad = await s.exchange({ subject_token: "not-a-jwt" });
    expect(await bad.json()).toEqual({
      error: "invalid_grant",
      error_description: "Invalid subject_token",
    });
    const denied = (await events()).filter((e) => e.outcome === "denied");
    expect(denied.map((e) => e.reason)).toEqual(["invalid_target", "invalid_subject_token"]);
  });
});
