// Integration test: real Postgres, no HTTP app.
import { applications, db, runMigrations, scopes, tokenEvents } from "@handsal/db";
import { eq } from "drizzle-orm";
import { decodeJwt } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { OAuthError } from "../middleware/error-handler.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import { issueToken } from "./token.service.js";

const AUD = "https://api.acme.io/payments";
const ctx = { sourceIp: "203.0.113.7" };

async function setup(resourceOver: { status?: "active" | "disabled" } = {}) {
  const tenant = await createTenant();
  const { application } = await createApplication(tenant.id);
  const { resource, scopes: created } = await createResourceWithScopes(
    tenant.id,
    AUD,
    ["payments:read", "payments:write"],
    resourceOver,
  );
  await grant(
    tenant.id,
    application.id,
    created.map((s) => s.id),
  );
  const [row] = await db.select().from(applications).where(eq(applications.id, application.id));
  const { clientSecretHash: _c, previousSecretHash: _p, ...app } = row;
  return { tenant, app: app as AuthenticatedApplication, resource };
}

async function reasonOf(promise: Promise<unknown>) {
  const err = (await promise.catch((e) => e)) as OAuthError;
  return { code: err.errorCode, status: err.statusCode, reason: err.reason };
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("issueToken", () => {
  it("dedupes requested scopes, records the event and sets last_token_at without touching updated_at", async () => {
    const { tenant, app } = await setup();
    const res = await issueToken(
      tenant,
      app,
      { audience: AUD, requestedScopes: ["payments:write", "payments:write"] },
      ctx,
    );
    expect(res.scope).toBe("payments:write");
    expect(decodeJwt(res.access_token).scope).toBe("payments:write");

    const [row] = await db.select().from(applications).where(eq(applications.id, app.id));
    expect(row.lastTokenAt).toBeInstanceOf(Date);
    expect(row.updatedAt.getTime()).toBe(app.updatedAt.getTime());

    const [event] = await db.select().from(tokenEvents);
    expect(event).toMatchObject({ outcome: "issued", sourceIp: ctx.sourceIp });
  });

  it("rejects a disabled resource as invalid_target", async () => {
    const { tenant, app } = await setup({ status: "disabled" });
    expect(await reasonOf(issueToken(tenant, app, { audience: AUD }, ctx))).toEqual({
      code: "invalid_target",
      status: 400,
      reason: "invalid_target",
    });
  });

  it("rejects never-policy scopes for agents only", async () => {
    const { tenant, app, resource } = await setup();
    await db.update(scopes).set({ agentPolicy: "never" }).where(eq(scopes.resourceId, resource.id));
    await db.update(scopes).set({ agentPolicy: "auto" }).where(eq(scopes.name, "payments:read"));
    const agent = { ...app, kind: "agent" as const };

    expect(
      await reasonOf(
        issueToken(tenant, agent, { audience: AUD, requestedScopes: ["payments:write"] }, ctx),
      ),
    ).toEqual({ code: "invalid_scope", status: 400, reason: "invalid_scope" });
    // Omitted scope ⇒ all granted, which includes the never scope.
    expect((await reasonOf(issueToken(tenant, agent, { audience: AUD }, ctx))).code).toBe(
      "invalid_scope",
    );
    const ok = await issueToken(
      tenant,
      agent,
      { audience: AUD, requestedScopes: ["payments:read"] },
      ctx,
    );
    expect(decodeJwt(ok.access_token).client_kind).toBe("agent");
    // A service may still get the never scope.
    expect(
      (await issueToken(tenant, app, { audience: AUD, requestedScopes: ["payments:write"] }, ctx))
        .scope,
    ).toBe("payments:write");
  });
});
