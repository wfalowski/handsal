// Integration test: real Postgres, plus a local Hono server standing in for an external IdP's JWKS.
import type { AddressInfo } from "node:net";
import { applications, db, revokedTokens, runMigrations, scopes, tokenEvents } from "@handsal/db";
import { ISSUED_TOKEN_TYPE } from "@handsal/shared";
import { type ServerType, serve } from "@hono/node-server";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { decodeJwt, exportJWK, generateKeyPair, type JWTPayload, SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { OAuthError } from "../middleware/error-handler.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.js";
import type { ApplicationCreateInput } from "./application.service.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import type { Tenant } from "./tenant.service.js";
import { issueToken, type TokenResponse } from "./token.service.js";
import { exchangeToken } from "./token-exchange.service.js";

const AUD = "https://api.acme.io/tickets";
const ctx = { sourceIp: "203.0.113.7" };
const IDP_ISSUER = "https://idp.example.com";
const IDP_AUDIENCE = "handsal";

let idpServer: ServerType;
let jwksUri: string;
let idpKey: CryptoKey;

async function signIdpToken(claims: JWTPayload) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: IDP_ISSUER,
    aud: IDP_AUDIENCE,
    sub: "user_9f2d",
    iat: now,
    exp: now + 300,
    ...claims,
  })
    .setProtectedHeader({ alg: "RS256", kid: "idp-1" })
    .sign(idpKey);
}

async function newApp(tenantId: string, over: Partial<ApplicationCreateInput>, scopeIds: string[]) {
  const { application } = await createApplication(tenantId, over);
  if (scopeIds.length) await grant(tenantId, application.id, scopeIds);
  const [row] = await db.select().from(applications).where(eq(applications.id, application.id));
  const { clientSecretHash: _c, previousSecretHash: _p, ...app } = row;
  return app as AuthenticatedApplication;
}

/** Tenant with tickets:{read,write,delete}; a service granted `read`, an agent granted read+write. */
async function setup(
  opts: {
    agent?: Partial<ApplicationCreateInput>;
    tenant?: Parameters<typeof createTenant>[0];
  } = {},
) {
  const tenant = (await createTenant({
    externalIdp: { issuer: IDP_ISSUER, jwksUri, audience: IDP_AUDIENCE },
    ...opts.tenant,
  })) as Tenant;
  const { resource, scopes: created } = await createResourceWithScopes(tenant.id, AUD, [
    "tickets:read",
    "tickets:write",
    "tickets:delete",
  ]);
  const [read, write] = created;
  const service = await newApp(tenant.id, {}, [read.id]);
  const agent = await newApp(
    tenant.id,
    { kind: "agent", mayActFor: ["services", "tenant", "users"], ...opts.agent },
    [read.id, write.id],
  );
  const subject = ((await issueToken(tenant, service, { audience: AUD }, ctx)) as TokenResponse)
    .access_token;
  return { tenant, resource, scopes: created, service, agent, subject };
}

async function reasonOf(promise: Promise<unknown>) {
  const err = (await promise.catch((e) => e)) as OAuthError;
  return { code: err.errorCode, status: err.statusCode };
}

beforeAll(async () => {
  await runMigrations();
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  idpKey = privateKey;
  const jwk = { ...(await exportJWK(publicKey)), kid: "idp-1", alg: "RS256", use: "sig" };
  const idp = new Hono().get("/jwks", (c) => c.json({ keys: [jwk] }));
  await new Promise<void>((resolve) => {
    idpServer = serve({ fetch: idp.fetch, port: 0, hostname: "127.0.0.1" }, () => resolve());
  });
  jwksUri = `http://127.0.0.1:${(idpServer.address() as AddressInfo).port}/jwks`;
});

afterAll(() => {
  idpServer.close();
});

beforeEach(async () => {
  await truncateAll();
});

describe("exchangeToken", () => {
  it("exchanges a Handsal service token and nests nothing", async () => {
    const { tenant, agent, service, subject } = await setup();
    const res = await exchangeToken(
      tenant,
      agent,
      { subjectToken: subject, audience: AUD, taskId: "task-42" },
      ctx,
    );
    expect(res).toMatchObject({
      issued_token_type: ISSUED_TOKEN_TYPE,
      token_type: "Bearer",
      scope: "tickets:read",
    });
    expect(decodeJwt(res.access_token)).toMatchObject({
      sub: service.clientId,
      act: { sub: agent.clientId },
      client_id: agent.clientId,
      client_kind: "agent",
      task_id: "task-42",
    });
  });

  it("nests act when the subject already carries one", async () => {
    const { tenant, scopes: s, agent, subject } = await setup();
    const first = await exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx);
    const second = await newApp(tenant.id, { kind: "agent", mayActFor: ["tenant"] }, [s[0].id]);
    const res = await exchangeToken(
      tenant,
      second,
      { subjectToken: first.access_token, audience: AUD },
      ctx,
    );
    expect(decodeJwt(res.access_token).act).toEqual({
      sub: second.clientId,
      act: { sub: agent.clientId },
    });
  });

  it("records actor_sub on the token event", async () => {
    const { tenant, agent, service, subject } = await setup();
    await exchangeToken(
      tenant,
      agent,
      { subjectToken: subject, audience: AUD, taskId: "t-1" },
      ctx,
    );
    const rows = await db.select().from(tokenEvents).where(eq(tokenEvents.applicationId, agent.id));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ outcome: "issued", actorSub: service.clientId, taskId: "t-1" });
  });

  it("revoked subject token → invalid_grant", async () => {
    const { tenant, agent, subject } = await setup();
    const { jti, exp } = decodeJwt(subject);
    await db.insert(revokedTokens).values({
      tenantId: tenant.id,
      jti: jti as string,
      expiresAt: new Date((exp as number) * 1000),
    });
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("subject token from another tenant → invalid_grant", async () => {
    const { subject } = await setup();
    const { tenant, agent } = await setup();
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("subject token issued before tokens_not_before → invalid_grant", async () => {
    const { tenant, agent, subject } = await setup();
    const marked = { ...tenant, tokensNotBefore: new Date(Date.now() + 5_000) };
    expect(
      await reasonOf(exchangeToken(marked, agent, { subjectToken: subject, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("intersection mode narrows to the overlap", async () => {
    const { tenant, agent } = await setup();
    const token = await signIdpToken({ scope: "tickets:write tickets:delete other" });
    const res = await exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx);
    expect(res.scope).toBe("tickets:write");
  });

  it("intersection with no overlap → invalid_scope", async () => {
    const { tenant, agent } = await setup();
    const token = await signIdpToken({ scope: "tickets:delete" });
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_scope", status: 400 });
  });

  it("intersection with a scopeless subject → invalid_scope", async () => {
    const { tenant, agent } = await setup();
    const token = await signIdpToken({});
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_scope", status: 400 });
  });

  it("explicit scope outside the intersection → invalid_scope", async () => {
    const { tenant, agent, subject } = await setup();
    expect(
      await reasonOf(
        exchangeToken(
          tenant,
          agent,
          { subjectToken: subject, audience: AUD, requestedScopes: ["tickets:write"] },
          ctx,
        ),
      ),
    ).toEqual({ code: "invalid_scope", status: 400 });
  });

  it("agent_only ignores the subject's scopes", async () => {
    const { tenant, agent } = await setup({ agent: { delegationScopeMode: "agent_only" } });
    const token = await signIdpToken({});
    const res = await exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx);
    expect(res.scope.split(" ").sort()).toEqual(["tickets:read", "tickets:write"]);
  });

  it("accepts scp as an array from an external IdP", async () => {
    const { tenant, agent } = await setup();
    const token = await signIdpToken({ scp: ["tickets:read", "tickets:write"] });
    const res = await exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx);
    expect(res.scope.split(" ").sort()).toEqual(["tickets:read", "tickets:write"]);
    expect(decodeJwt(res.access_token)).toMatchObject({
      sub: "user_9f2d",
      act: { sub: agent.clientId },
    });
  });

  it("external token with the wrong issuer or audience, or no IdP configured → invalid_grant", async () => {
    const { tenant, agent } = await setup();
    for (const claims of [{ iss: "https://evil.example.com" }, { aud: "someone-else" }]) {
      const token = await signIdpToken({ ...claims, scope: "tickets:read" });
      expect(
        await reasonOf(exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx)),
      ).toEqual({ code: "invalid_grant", status: 400 });
    }
    const token = await signIdpToken({ scope: "tickets:read" });
    expect(
      await reasonOf(
        exchangeToken(
          { ...tenant, externalIdp: null },
          agent,
          { subjectToken: token, audience: AUD },
          ctx,
        ),
      ),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("external subject rejected when may_act_for lacks users → unauthorized_client", async () => {
    const { tenant, agent } = await setup({ agent: { mayActFor: ["tenant"] } });
    const token = await signIdpToken({ scope: "tickets:read" });
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx)),
    ).toEqual({ code: "unauthorized_client", status: 400 });
  });

  it("agent subject rejected when may_act_for is services only → unauthorized_client", async () => {
    const { tenant, agent } = await setup();
    const own = (await issueToken(tenant, agent, { audience: AUD }, ctx)) as TokenResponse;
    const narrow = await newApp(tenant.id, { kind: "agent", mayActFor: ["services"] }, []);
    expect(
      await reasonOf(
        exchangeToken(tenant, narrow, { subjectToken: own.access_token, audience: AUD }, ctx),
      ),
    ).toEqual({ code: "unauthorized_client", status: 400 });
  });

  it("user-originated delegated token cannot be re-exchanged without users (two hops)", async () => {
    const { tenant, agent, scopes: s } = await setup();
    const idp = await signIdpToken({ scope: "tickets:read" });
    const first = await exchangeToken(tenant, agent, { subjectToken: idp, audience: AUD }, ctx);
    const second = await newApp(tenant.id, { kind: "agent", mayActFor: ["tenant", "services"] }, [
      s[0].id,
    ]);
    expect(
      await reasonOf(
        exchangeToken(tenant, second, { subjectToken: first.access_token, audience: AUD }, ctx),
      ),
    ).toEqual({ code: "unauthorized_client", status: 400 });
  });

  it("sub_kind is set from the subject and sticky across re-exchanges", async () => {
    const { tenant, agent, subject } = await setup();
    const first = await exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx);
    expect(decodeJwt(first.access_token).sub_kind).toBe("service");
    const second = await exchangeToken(
      tenant,
      agent,
      { subjectToken: first.access_token, audience: AUD },
      ctx,
    );
    expect(decodeJwt(second.access_token).sub_kind).toBe("service");
    const own = (await issueToken(tenant, agent, { audience: AUD }, ctx)) as TokenResponse;
    const fromAgent = await exchangeToken(
      tenant,
      agent,
      { subjectToken: own.access_token, audience: AUD },
      ctx,
    );
    expect(decodeJwt(fromAgent.access_token).sub_kind).toBe("agent");
    const idp = await signIdpToken({ scope: "tickets:read" });
    const fromUser = await exchangeToken(tenant, agent, { subjectToken: idp, audience: AUD }, ctx);
    expect(decodeJwt(fromUser.access_token).sub_kind).toBe("user");
  });

  it("an external IdP's act is not copied into the issued chain", async () => {
    const { tenant, agent } = await setup();
    const idp = await signIdpToken({ scope: "tickets:read", act: { sub: "svc_payments" } });
    const res = await exchangeToken(tenant, agent, { subjectToken: idp, audience: AUD }, ctx);
    expect(decodeJwt(res.access_token).act).toEqual({ sub: agent.clientId });
  });

  it("act chain deeper than 3 → invalid_grant", async () => {
    const { tenant, agent, subject } = await setup();
    let token = subject;
    for (let i = 0; i < 3; i++) {
      token = (await exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx))
        .access_token;
    }
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("Handsal subject for another resource → invalid_grant, even with a shared scope name", async () => {
    const { tenant, agent, subject } = await setup();
    const other = "https://api.acme.io/payroll";
    const { scopes: payroll } = await createResourceWithScopes(tenant.id, other, ["tickets:read"]);
    await grant(tenant.id, agent.id, [payroll[0].id]);
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: subject, audience: other }, ctx)),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("delegated lifetime is capped by a subject that expires before the agent TTL", async () => {
    const { tenant, agent } = await setup({ agent: { tokenTtlSeconds: 900 } });
    const now = Math.floor(Date.now() / 1000);
    const short = await signIdpToken({ scope: "tickets:read", exp: now + 20 });
    const res = await exchangeToken(tenant, agent, { subjectToken: short, audience: AUD }, ctx);
    expect(res.expires_in).toBeGreaterThanOrEqual(15);
    expect(res.expires_in).toBeLessThanOrEqual(20);
    const issued = decodeJwt(res.access_token);
    expect(issued.exp).toBe((issued.iat as number) + res.expires_in);
    expect(issued.exp).toBeLessThanOrEqual((decodeJwt(short).exp as number) + 1);

    const long = await signIdpToken({ scope: "tickets:read", exp: now + 7200 });
    const capped = await exchangeToken(tenant, agent, { subjectToken: long, audience: AUD }, ctx);
    expect(capped.expires_in).toBe(900);

    const dying = await signIdpToken({ scope: "tickets:read", exp: now });
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: dying, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("external JWT without exp → invalid_grant", async () => {
    const { tenant, agent } = await setup();
    const token = await signIdpToken({ scope: "tickets:read", exp: undefined });
    expect(decodeJwt(token).exp).toBeUndefined();
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_grant", status: 400 });
  });

  it("accepts scope as an array from an external IdP", async () => {
    const { tenant, agent } = await setup();
    const token = await signIdpToken({ scope: ["tickets:read"] });
    const res = await exchangeToken(tenant, agent, { subjectToken: token, audience: AUD }, ctx);
    expect(res.scope).toBe("tickets:read");
  });

  it("non-agent application or empty may_act_for → unauthorized_client", async () => {
    const { tenant, service, subject } = await setup();
    const idle = await newApp(tenant.id, { kind: "agent" }, []);
    for (const app of [service, idle]) {
      expect(
        await reasonOf(exchangeToken(tenant, app, { subjectToken: subject, audience: AUD }, ctx)),
      ).toEqual({ code: "unauthorized_client", status: 400 });
    }
  });

  it("foreign resource → invalid_target", async () => {
    const { tenant, agent } = await setup();
    const other = await createTenant();
    await createResourceWithScopes(other.id, "https://api.other.io", ["x:read"]);
    // External subject: a Handsal subject would already fail the aud pin (invalid_grant).
    const subject = await signIdpToken({ scope: "x:read" });
    expect(
      await reasonOf(
        exchangeToken(
          tenant,
          agent,
          { subjectToken: subject, audience: "https://api.other.io" },
          ctx,
        ),
      ),
    ).toEqual({ code: "invalid_target", status: 400 });
  });

  it("approval scope → invalid_scope, not queued", async () => {
    const { tenant, agent, subject, scopes: s } = await setup();
    await db.update(scopes).set({ agentPolicy: "approval" }).where(eq(scopes.id, s[0].id));
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_scope", status: 400 });
  });

  it("never scope → invalid_scope", async () => {
    const { tenant, agent, subject, scopes: s } = await setup();
    await db.update(scopes).set({ agentPolicy: "never" }).where(eq(scopes.id, s[0].id));
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx)),
    ).toEqual({ code: "invalid_scope", status: 400 });
  });

  it("agent guardrails apply (max scopes per token, hourly budget)", async () => {
    const capped = await setup({
      agent: { delegationScopeMode: "agent_only", maxScopesPerToken: 1 },
    });
    expect(
      await reasonOf(
        exchangeToken(
          capped.tenant,
          capped.agent,
          { subjectToken: capped.subject, audience: AUD },
          ctx,
        ),
      ),
    ).toEqual({ code: "invalid_scope", status: 400 });

    const { tenant, agent, subject } = await setup({ agent: { tokenBudgetPerHour: 1 } });
    await exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx);
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx)),
    ).toEqual({ code: "too_many_requests", status: 429 });
  });

  it("agent guardrails apply (source CIDR)", async () => {
    const { tenant, agent, subject } = await setup({ agent: { allowedCidrs: ["10.0.0.0/8"] } });
    expect(
      await reasonOf(exchangeToken(tenant, agent, { subjectToken: subject, audience: AUD }, ctx)),
    ).toEqual({ code: "unauthorized_client", status: 400 });
  });
});
