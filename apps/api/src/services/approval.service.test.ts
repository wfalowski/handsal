// Integration test: real Postgres, no HTTP app.
import {
  applicationGrants,
  applications,
  approvalRequests,
  db,
  runMigrations,
  scopes,
  tokenEvents,
} from "@handsal/db";
import { and, eq, inArray } from "drizzle-orm";
import { decodeJwt } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { OAuthError } from "../middleware/error-handler.js";
import {
  createApplication,
  createApprovalRequest,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.js";
import { decideApproval } from "./approval.service.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import {
  issueToken,
  type PendingApproval,
  redeemApproval,
  type TokenResponse,
} from "./token.service.js";

const AUD = "https://api.acme.io/payments";
const ctx = { sourceIp: "203.0.113.7" };
const apiKey = { kind: "api-key", isSuperAdmin: true } as const;

/** Agent granted read (auto), write (approval), refund (never). */
async function setup() {
  const tenant = await createTenant();
  const { application } = await createApplication(tenant.id, { kind: "agent" });
  const { resource, scopes: created } = await createResourceWithScopes(tenant.id, AUD, [
    "payments:read",
    "payments:refund",
    "payments:write",
  ]);
  await db.update(scopes).set({ agentPolicy: "approval" }).where(eq(scopes.id, created[2].id));
  await db.update(scopes).set({ agentPolicy: "never" }).where(eq(scopes.id, created[1].id));
  await grant(
    tenant.id,
    application.id,
    created.map((s) => s.id),
  );
  const [row] = await db.select().from(applications).where(eq(applications.id, application.id));
  const { clientSecretHash: _c, previousSecretHash: _p, ...app } = row;
  return { tenant, app: app as AuthenticatedApplication, resource, scopes: created };
}

async function reasonOf(promise: Promise<unknown>) {
  const err = (await promise.catch((e) => e)) as OAuthError;
  return { code: err.errorCode, status: err.statusCode, reason: err.reason };
}

async function requestWrite(s: Awaited<ReturnType<typeof setup>>, extra = {}) {
  return (await issueToken(
    s.tenant,
    s.app,
    { audience: AUD, requestedScopes: ["payments:write"], ...extra },
    ctx,
  )) as PendingApproval;
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("approval requests", () => {
  it("creates a pending row and records a pending token event", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s, {
      taskId: "run-7",
      actorHint: "alice@example.com",
      justification: "refund batch",
    });
    const rows = await db.select().from(approvalRequests);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      id: approvalId,
      tenantId: s.tenant.id,
      applicationId: s.app.id,
      resourceId: s.resource.id,
      audience: AUD,
      scopes: ["payments:write"],
      status: "pending",
      taskId: "run-7",
      actorHint: "alice@example.com",
      justification: "refund batch",
    });
    const ttl = rows[0].expiresAt.getTime() - rows[0].createdAt.getTime();
    expect(Math.abs(ttl - 30 * 60_000)).toBeLessThan(5_000);
    const events = await db.select().from(tokenEvents);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      outcome: "pending",
      scopes: ["payments:write"],
      taskId: "run-7",
      jti: null,
    });
  });

  it("reuses the pending row for an identical repeated request", async () => {
    const s = await setup();
    const a = await requestWrite(s);
    const b = await requestWrite(s);
    expect(b.approvalId).toBe(a.approvalId);
    expect(await db.select().from(approvalRequests)).toHaveLength(1);
    // A different task opens its own card.
    const c = await requestWrite(s, { taskId: "other" });
    expect(c.approvalId).not.toBe(a.approvalId);
  });

  it("mixed auto and approval scopes go pending as a whole", async () => {
    const s = await setup();
    const res = (await issueToken(
      s.tenant,
      s.app,
      { audience: AUD, requestedScopes: ["payments:read", "payments:write"] },
      ctx,
    )) as PendingApproval;
    expect(res.approvalId).toEqual(expect.any(String));
    const [row] = await db.select().from(approvalRequests);
    expect(row.scopes).toEqual(["payments:read", "payments:write"]);
    // Auto-only still issues directly.
    const auto = (await issueToken(
      s.tenant,
      s.app,
      { audience: AUD, requestedScopes: ["payments:read"] },
      ctx,
    )) as TokenResponse;
    expect(auto.scope).toBe("payments:read");
  });

  it("never beats approval", async () => {
    const s = await setup();
    const res = await reasonOf(
      issueToken(
        s.tenant,
        s.app,
        { audience: AUD, requestedScopes: ["payments:refund", "payments:write"] },
        ctx,
      ),
    );
    expect(res.code).toBe("invalid_scope");
    expect(await db.select().from(approvalRequests)).toHaveLength(0);
  });

  it("guardrails run before the approval queue", async () => {
    const s = await setup();
    const blocked = { ...s.app, allowedCidrs: ["10.0.0.0/8"] };
    const res = await reasonOf(
      issueToken(s.tenant, blocked, { audience: AUD, requestedScopes: ["payments:write"] }, ctx),
    );
    expect(res.reason).toBe("cidr_denied");
    expect(await db.select().from(approvalRequests)).toHaveLength(0);
  });

  it("a service application ignores approval scopes", async () => {
    const s = await setup();
    const service = { ...s.app, kind: "service" as const };
    const res = (await issueToken(
      s.tenant,
      service,
      { audience: AUD, requestedScopes: ["payments:write"] },
      ctx,
    )) as TokenResponse;
    expect(res.scope).toBe("payments:write");
  });
});

describe("redeemApproval", () => {
  it("pending → marker; redeem issues exactly one token", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s, { taskId: "run-9" });
    expect(await redeemApproval(s.tenant, s.app, approvalId, ctx)).toEqual({ approvalId });

    await decideApproval(s.tenant.id, approvalId, "approved", apiKey);
    const first = (await redeemApproval(s.tenant, s.app, approvalId, ctx)) as TokenResponse;
    expect(first.expires_in).toBe(300);
    expect(first.scope).toBe("payments:write");
    const payload = decodeJwt(first.access_token);
    expect(payload).toMatchObject({ scope: "payments:write", aud: AUD, task_id: "run-9" });
    expect((payload.exp as number) - (payload.iat as number)).toBe(300);

    expect(await reasonOf(redeemApproval(s.tenant, s.app, approvalId, ctx))).toMatchObject({
      code: "invalid_grant",
    });
    const issued = await db.select().from(tokenEvents).where(eq(tokenEvents.outcome, "issued"));
    expect(issued).toHaveLength(1);
    expect(issued[0].taskId).toBe("run-9");
  });

  it("concurrent polls: only one wins", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s);
    await decideApproval(s.tenant.id, approvalId, "approved", apiKey);
    const results = await Promise.allSettled(
      Array.from({ length: 5 }, () => redeemApproval(s.tenant, s.app, approvalId, ctx)),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    for (const r of results) {
      if (r.status === "rejected") expect((r.reason as OAuthError).errorCode).toBe("invalid_grant");
    }
  });

  it("grant revoked during the window → invalid_grant", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s);
    await decideApproval(s.tenant.id, approvalId, "approved", apiKey);
    await db
      .delete(applicationGrants)
      .where(
        and(
          eq(applicationGrants.applicationId, s.app.id),
          inArray(applicationGrants.scopeId, [s.scopes[2].id]),
        ),
      );
    expect((await reasonOf(redeemApproval(s.tenant, s.app, approvalId, ctx))).code).toBe(
      "invalid_grant",
    );
  });

  it("expired row → expired_token (status or past expires_at)", async () => {
    const s = await setup();
    const past = new Date(Date.now() - 1000);
    const overdue = await createApprovalRequest(s.tenant.id, s.app.id, s.resource.id, {
      expiresAt: past,
    });
    const marked = await createApprovalRequest(s.tenant.id, s.app.id, s.resource.id, {
      status: "expired",
      expiresAt: past,
    });
    for (const id of [overdue.id, marked.id]) {
      expect((await reasonOf(redeemApproval(s.tenant, s.app, id, ctx))).code).toBe("expired_token");
    }
  });

  it("denied row → access_denied; unknown and foreign ids → invalid_grant", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s);
    await decideApproval(s.tenant.id, approvalId, "denied", apiKey);
    expect((await reasonOf(redeemApproval(s.tenant, s.app, approvalId, ctx))).code).toBe(
      "access_denied",
    );

    const other = await setup();
    const unknown = "00000000-0000-4000-8000-000000000000";
    expect((await reasonOf(redeemApproval(s.tenant, s.app, unknown, ctx))).code).toBe(
      "invalid_grant",
    );
    expect((await reasonOf(redeemApproval(other.tenant, other.app, approvalId, ctx))).code).toBe(
      "invalid_grant",
    );
  });
});
