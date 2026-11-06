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
import type { ApplicationCreateInput } from "./application.service.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import { issueToken as issueAny, type TokenResponse } from "./token.service.js";

const AUD = "https://api.acme.io/payments";
const ctx = { sourceIp: "203.0.113.7" };
// Existing cases never hit an approval scope.
const issueToken = (...args: Parameters<typeof issueAny>) =>
  issueAny(...args) as Promise<TokenResponse>;

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

const SCOPES = ["payments:read", "payments:refund", "payments:write"];

async function agentSetup(over: Partial<ApplicationCreateInput> = {}) {
  const tenant = await createTenant();
  const { application } = await createApplication(tenant.id, { kind: "agent", ...over });
  const { scopes: created } = await createResourceWithScopes(tenant.id, AUD, SCOPES);
  await grant(
    tenant.id,
    application.id,
    created.map((s) => s.id),
  );
  const [row] = await db.select().from(applications).where(eq(applications.id, application.id));
  const { clientSecretHash: _c, previousSecretHash: _p, ...app } = row;
  return { tenant, app: app as AuthenticatedApplication };
}

const issuedEvent = (tenantId: string, applicationId: string, createdAt?: Date) =>
  db.insert(tokenEvents).values({ tenantId, applicationId, outcome: "issued", createdAt });

describe("agent guardrails", () => {
  it("source IP must be in allowed_cidrs (IPv4, IPv6, IPv4-mapped); empty list allows any", async () => {
    const { tenant, app } = await agentSetup({ allowedCidrs: ["10.40.0.0/16", "2001:db8::/32"] });
    const req = { audience: AUD, requestedScopes: ["payments:read"] };
    for (const sourceIp of ["10.40.1.2", "::ffff:10.40.0.5", "2001:db8::1"]) {
      expect((await issueToken(tenant, app, req, { sourceIp })).scope).toBe("payments:read");
    }
    for (const sourceIp of ["10.41.0.1", "2001:db9::1", "unknown"]) {
      expect(await reasonOf(issueToken(tenant, app, req, { sourceIp }))).toEqual({
        code: "unauthorized_client",
        status: 400,
        reason: "cidr_denied",
      });
    }

    const open = await agentSetup();
    expect(open.app.allowedCidrs).toEqual([]);
    await expect(issueToken(open.tenant, open.app, req, ctx)).resolves.toBeDefined();
  });

  it("a malformed stored CIDR fails closed", async () => {
    const { tenant, app } = await agentSetup();
    const corrupt = { ...app, allowedCidrs: ["10.40.0.0/99"] };
    const res = await reasonOf(issueToken(tenant, corrupt, { audience: AUD }, ctx));
    // Distinct reason: config corruption, not an off-network agent; same OAuth error.
    expect(res).toEqual({ code: "unauthorized_client", status: 400, reason: "cidr_invalid" });
  });

  it("scope ceiling: N scopes pass, N+1 are invalid_scope; omitted scope counts the whole grant", async () => {
    const { tenant, app } = await agentSetup({ maxScopesPerToken: 2 });
    const two = await issueToken(
      tenant,
      app,
      { audience: AUD, requestedScopes: ["payments:read", "payments:write"] },
      ctx,
    );
    expect(two.scope).toBe("payments:read payments:write");
    const ceiling = { code: "invalid_scope", status: 400, reason: "scope_ceiling" };
    expect(
      await reasonOf(issueToken(tenant, app, { audience: AUD, requestedScopes: SCOPES }, ctx)),
    ).toEqual(ceiling);
    expect(await reasonOf(issueToken(tenant, app, { audience: AUD }, ctx))).toEqual(ceiling);
  });

  it("hourly budget: requests 1-3 pass, 4 is 429 with retryAfterSeconds", async () => {
    const { tenant, app } = await agentSetup({ tokenBudgetPerHour: 3 });
    const req = { audience: AUD, requestedScopes: ["payments:read"] };
    for (let i = 0; i < 3; i++) await issueToken(tenant, app, req, ctx);
    const err = (await issueToken(tenant, app, req, ctx).catch((e) => e)) as OAuthError;
    expect({ code: err.errorCode, status: err.statusCode, reason: err.reason }).toEqual({
      code: "too_many_requests",
      status: 429,
      reason: "budget_exhausted",
    });
    expect(err.retryAfterSeconds).toBeGreaterThan(3500);
    expect(err.retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("budget ignores events older than an hour, denied events and other applications", async () => {
    const { tenant, app } = await agentSetup({ tokenBudgetPerHour: 1 });
    await issuedEvent(tenant.id, app.id, new Date(Date.now() - 61 * 60_000));
    await db
      .insert(tokenEvents)
      .values({ tenantId: tenant.id, applicationId: app.id, outcome: "denied" });
    const other = await createApplication(tenant.id);
    await issuedEvent(tenant.id, other.application.id);
    await expect(issueToken(tenant, app, { audience: AUD }, ctx)).resolves.toBeDefined();
    expect((await reasonOf(issueToken(tenant, app, { audience: AUD }, ctx))).reason).toBe(
      "budget_exhausted",
    );
  });

  it("guardrails run after resource resolution: ungranted resource from a bad IP is invalid_target", async () => {
    const { tenant, app } = await agentSetup({ allowedCidrs: ["10.40.0.0/16"] });
    const res = await reasonOf(
      issueToken(tenant, app, { audience: "https://nope" }, { sourceIp: "1.1.1.1" }),
    );
    expect(res.code).toBe("invalid_target");
  });

  it("a service application ignores populated guardrail columns", async () => {
    const { tenant, app } = await agentSetup();
    await db
      .update(applications)
      .set({
        kind: "service",
        allowedCidrs: ["10.40.0.0/16"],
        maxScopesPerToken: 1,
        tokenBudgetPerHour: 1,
      })
      .where(eq(applications.id, app.id));
    const [row] = await db.select().from(applications).where(eq(applications.id, app.id));
    const service = row as AuthenticatedApplication;
    for (let i = 0; i < 3; i++) {
      const res = await issueToken(tenant, service, { audience: AUD }, { sourceIp: "1.1.1.1" });
      expect(res.scope.split(" ")).toHaveLength(3);
    }
  });
});

describe("taskId", () => {
  it("emits the task_id claim and stores it on the event only when given", async () => {
    const { tenant, app } = await setup();
    const withTask = await issueToken(tenant, app, { audience: AUD, taskId: "run-42" }, ctx);
    expect(decodeJwt(withTask.access_token).task_id).toBe("run-42");
    const without = await issueToken(tenant, app, { audience: AUD }, ctx);
    expect(decodeJwt(without.access_token)).not.toHaveProperty("task_id");
    const events = await db.select().from(tokenEvents).orderBy(tokenEvents.id);
    expect(events.map((e) => e.taskId)).toEqual(["run-42", null]);
  });
});
