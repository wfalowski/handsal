// Integration test: real Postgres, no HTTP app.
import {
  adminUsers,
  applicationGrants,
  applications,
  approvalRequests,
  approvalRules,
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
  createAdminUser,
  createApplication,
  createApprovalRequest,
  createApprovalRule,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.js";
import { decideApproval, listApprovals } from "./approval.service.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import {
  issueToken,
  type PendingApproval,
  redeemApproval,
  type TokenResponse,
} from "./token.service.js";

const AUD = "https://api.acme.io/payments";
const ctx = { sourceIp: "203.0.113.7" };

async function decider() {
  const { user } = await createAdminUser({ name: "Decider" });
  return {
    kind: "user" as const,
    userId: user.id,
    email: user.email,
    name: user.name,
    isSuperAdmin: false,
  };
}

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
    // So does a different story: the human consents to the text on the card.
    const d = await requestWrite(s, { justification: "something else" });
    const e = await requestWrite(s, { actorHint: "bob@example.com" });
    expect(new Set([a.approvalId, d.approvalId, e.approvalId]).size).toBe(3);
  });

  it("caps live pending approvals per application", async () => {
    const s = await setup();
    for (let i = 0; i < 20; i++) {
      await createApprovalRequest(s.tenant.id, s.app.id, s.resource.id, { taskId: `t-${i}` });
    }
    expect(await reasonOf(requestWrite(s))).toMatchObject({
      code: "access_denied",
      reason: "approval_queue_full",
    });
    // Expired rows do not count.
    await db
      .update(approvalRequests)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(approvalRequests.taskId, "t-0"));
    expect((await requestWrite(s)).status).toBe("pending");
  });

  it("decided_by_label keeps the decider's name after the user is deleted", async () => {
    const s = await setup();
    const { user } = await createAdminUser({ name: "Jane Admin" });
    const { approvalId } = await requestWrite(s);
    const actor = {
      kind: "user",
      userId: user.id,
      email: user.email,
      name: user.name,
      isSuperAdmin: false,
    } as const;
    await decideApproval(s.tenant.id, approvalId, "approved", actor);
    await db.delete(adminUsers).where(eq(adminUsers.id, user.id));
    const list = await listApprovals(s.tenant.id, { status: "resolved", limit: 50 });
    expect(list.items[0].decidedBy).toEqual({ kind: "user", label: "Jane Admin" });
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
    expect(await redeemApproval(s.tenant, s.app, approvalId, ctx)).toEqual({
      approvalId,
      status: "pending",
    });

    await decideApproval(s.tenant.id, approvalId, "approved", await decider());
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
    expect(issued[0]).toMatchObject({ taskId: "run-9", reason: "approval" });
  });

  it("scope demoted to never or ceiling lowered during the window → denied", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s);
    await decideApproval(s.tenant.id, approvalId, "approved", await decider());
    await db.update(scopes).set({ agentPolicy: "never" }).where(eq(scopes.id, s.scopes[2].id));
    expect(await reasonOf(redeemApproval(s.tenant, s.app, approvalId, ctx))).toMatchObject({
      code: "invalid_grant",
      reason: "policy_changed",
    });

    await db.update(scopes).set({ agentPolicy: "approval" }).where(eq(scopes.id, s.scopes[2].id));
    const next = await requestWrite(s, { taskId: "t-2" });
    await decideApproval(s.tenant.id, next.approvalId, "approved", await decider());
    const capped = { ...s.app, maxScopesPerToken: 0 };
    expect(await reasonOf(redeemApproval(s.tenant, capped, next.approvalId, ctx))).toMatchObject({
      code: "invalid_scope",
      reason: "scope_ceiling",
    });
  });

  it("source outside allowed_cidrs → unauthorized_client, approval not consumed", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s);
    await decideApproval(s.tenant.id, approvalId, "approved", await decider());
    const pinned = { ...s.app, allowedCidrs: ["10.0.0.0/8"] };
    expect(await reasonOf(redeemApproval(s.tenant, pinned, approvalId, ctx))).toMatchObject({
      code: "unauthorized_client",
      reason: "cidr_denied",
    });
    const inside = { sourceIp: "10.1.2.3" };
    expect(await redeemApproval(s.tenant, pinned, approvalId, inside)).toHaveProperty(
      "access_token",
    );
  });

  it("hourly budget spent → 429 budget_exhausted with Retry-After", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s);
    await decideApproval(s.tenant.id, approvalId, "approved", await decider());
    const budgeted = { ...s.app, tokenBudgetPerHour: 1 };
    await issueToken(
      s.tenant,
      budgeted,
      { audience: AUD, requestedScopes: ["payments:read"] },
      ctx,
    );
    const err = (await redeemApproval(s.tenant, budgeted, approvalId, ctx).catch(
      (e) => e,
    )) as OAuthError;
    expect(err).toMatchObject({
      errorCode: "too_many_requests",
      statusCode: 429,
      reason: "budget_exhausted",
    });
    expect(err.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("concurrent polls: only one wins", async () => {
    const s = await setup();
    const { approvalId } = await requestWrite(s);
    await decideApproval(s.tenant.id, approvalId, "approved", await decider());
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
    await decideApproval(s.tenant.id, approvalId, "approved", await decider());
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
    await decideApproval(s.tenant.id, approvalId, "denied", await decider());
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

describe("auto-approve rules", () => {
  const write = (s: Awaited<ReturnType<typeof setup>>) => s.scopes[2];
  const rowOf = async (id: string) =>
    (await db.select().from(approvalRequests).where(eq(approvalRequests.id, id)))[0];

  it("a matching rule creates an approved row with decided_by_rule_id; DTO and counts show it", async () => {
    const s = await setup();
    const rule = await createApprovalRule(s.tenant.id, write(s).id, { task_id_prefix: "refund-" });
    const { approvalId } = await requestWrite(s, { taskId: "refund-1" });
    const row = await rowOf(approvalId);
    expect(row).toMatchObject({ status: "approved", decidedByRuleId: rule.id, decidedBy: null });
    expect(row.decidedAt).toBeInstanceOf(Date);
    // Still recorded as a pending event so the Tokens page shows the request.
    expect((await db.select().from(tokenEvents))[0].outcome).toBe("pending");

    const list = await listApprovals(s.tenant.id, { status: "resolved", limit: 50 });
    expect(list.items[0].decidedBy).toEqual({ kind: "rule", label: "rule: payments:write" });
    expect(list.counts.rules).toBe(1);
  });

  it("a re-sent request reuses the unredeemed rule-approved row", async () => {
    const s = await setup();
    await createApprovalRule(s.tenant.id, write(s).id);
    const a = await requestWrite(s);
    const b = await requestWrite(s);
    expect(b).toEqual({ approvalId: a.approvalId, status: "approved" });
    expect(await db.select().from(approvalRequests)).toHaveLength(1);
    // Once redeemed, the same request opens a new row.
    await redeemApproval(s.tenant, s.app, a.approvalId, ctx);
    expect((await requestWrite(s)).approvalId).not.toBe(a.approvalId);
  });

  it("the rule-approved row still issues exactly once", async () => {
    const s = await setup();
    await createApprovalRule(s.tenant.id, write(s).id);
    const { approvalId } = await requestWrite(s);
    const token = (await redeemApproval(s.tenant, s.app, approvalId, ctx)) as TokenResponse;
    expect(token.scope).toBe("payments:write");
    expect((await reasonOf(redeemApproval(s.tenant, s.app, approvalId, ctx))).code).toBe(
      "invalid_grant",
    );
  });

  it("a non-matching rule leaves the row pending (per condition key)", async () => {
    const s = await setup();
    const other = await createApplication(s.tenant.id, { kind: "agent" });
    await createApprovalRule(s.tenant.id, write(s).id, {
      application_ids: [other.application.id],
    });
    await createApprovalRule(s.tenant.id, write(s).id, { task_id_prefix: "refund-" });
    await createApprovalRule(s.tenant.id, write(s).id, { max_scopes: 1 });
    // Wrong app, null task id, two scopes: every rule fails one key.
    const res = (await issueToken(
      s.tenant,
      s.app,
      { audience: AUD, requestedScopes: ["payments:read", "payments:write"] },
      ctx,
    )) as PendingApproval;
    expect(await rowOf(res.approvalId)).toMatchObject({ status: "pending", decidedByRuleId: null });
  });

  it("every approval scope needs its own matching rule", async () => {
    const s = await setup();
    await db.update(scopes).set({ agentPolicy: "approval" }).where(eq(scopes.id, s.scopes[1].id));
    await createApprovalRule(s.tenant.id, write(s).id);
    const both = { audience: AUD, requestedScopes: ["payments:refund", "payments:write"] };
    const first = (await issueToken(s.tenant, s.app, both, ctx)) as PendingApproval;
    expect((await rowOf(first.approvalId)).status).toBe("pending");

    await createApprovalRule(s.tenant.id, s.scopes[1].id);
    const second = (await issueToken(
      s.tenant,
      s.app,
      { ...both, taskId: "t-2" },
      ctx,
    )) as PendingApproval;
    expect((await rowOf(second.approvalId)).status).toBe("approved");
  });

  it("a rule of another tenant never matches", async () => {
    const s = await setup();
    const other = await setup();
    await createApprovalRule(other.tenant.id, write(other).id);
    const { approvalId } = await requestWrite(s);
    expect((await rowOf(approvalId)).status).toBe("pending");
  });

  it("deleting the rule leaves decided_by_rule_id null and the row approved", async () => {
    const s = await setup();
    const rule = await createApprovalRule(s.tenant.id, write(s).id);
    const { approvalId } = await requestWrite(s);
    await db.delete(approvalRules).where(eq(approvalRules.id, rule.id));
    expect(await rowOf(approvalId)).toMatchObject({ status: "approved", decidedByRuleId: null });
  });
});
