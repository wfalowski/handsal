// Integration test: real Postgres through the full app.
import { db, revokedTokens, runMigrations, tokenEvents } from "@handsal/db";
import { eq } from "drizzle-orm";
import { decodeJwt } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../app.js";
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

async function setup() {
  const tenant = await createTenant();
  const { application, clientSecret } = await createApplication(tenant.id);
  const { scopes } = await createResourceWithScopes(tenant.id, PAYMENTS, ["payments:read"]);
  await grant(tenant.id, application.id, [scopes[0].id]);
  const other = await createApplication(tenant.id);
  return {
    tenant,
    application,
    auth: { Authorization: basic(application.clientId, clientSecret) },
    otherAuth: { Authorization: basic(other.application.clientId, other.clientSecret) },
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

const revoke = (slug: string, fields: Record<string, string>, auth: Record<string, string> = {}) =>
  formRequest(app, `/t/${slug}/oauth/revoke`, fields, auth);

const revokedEvents = () => db.select().from(tokenEvents).where(eq(tokenEvents.outcome, "revoked"));

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("POST /t/:slug/oauth/revoke", () => {
  it("revokes the caller's own token: 200 empty body, row + event recorded, idempotent", async () => {
    const { tenant, application, auth } = await setup();
    const token = await issue(tenant.slug, auth);
    const claims = decodeJwt(token);

    const res = await revoke(tenant.slug, { token }, auth);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(await res.text()).toBe("");

    expect(await db.select().from(revokedTokens)).toEqual([
      { jti: claims.jti, tenantId: tenant.id, expiresAt: new Date((claims.exp as number) * 1000) },
    ]);
    const [event] = await revokedEvents();
    expect(event).toMatchObject({
      tenantId: tenant.id,
      applicationId: application.id,
      applicationClientId: application.clientId,
      audience: PAYMENTS,
      outcome: "revoked",
      scopes: ["payments:read"],
      jti: claims.jti,
    });

    expect((await revoke(tenant.slug, { token }, auth)).status).toBe(200);
    expect(await db.select().from(revokedTokens)).toHaveLength(1);
  });

  it("ignores someone else's token: 200, no row, no event", async () => {
    const { tenant, auth, otherAuth } = await setup();
    const token = await issue(tenant.slug, auth);
    const res = await revoke(tenant.slug, { token }, otherAuth);
    expect(res.status).toBe(200);
    expect(await db.select().from(revokedTokens)).toHaveLength(0);
    expect(await revokedEvents()).toHaveLength(0);
  });

  it("answers 200 for a garbage token", async () => {
    const { tenant, auth } = await setup();
    expect((await revoke(tenant.slug, { token: "garbage" }, auth)).status).toBe(200);
    expect(await revokedEvents()).toHaveLength(0);
  });

  it("returns 401 for unauthenticated callers", async () => {
    const { tenant, auth } = await setup();
    const token = await issue(tenant.slug, auth);
    const res = await revoke(tenant.slug, { token });
    expect(res.status).toBe(401);
    expect(await db.select().from(revokedTokens)).toHaveLength(0);
  });

  it("returns 400 without a token parameter", async () => {
    const { tenant, auth } = await setup();
    expect((await revoke(tenant.slug, {}, auth)).status).toBe(400);
  });
});
