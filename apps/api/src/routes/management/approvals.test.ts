// Integration test: real Postgres through the full app.
import { approvalRequests, db, pool, runMigrations } from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import {
  addMember,
  createAdminUser,
  createApplication,
  createApprovalRequest,
  createResourceWithScopes,
  createTenant,
  truncateAll,
} from "../../test/factories.js";
import { jsonRequest, loginAs } from "../../test/helpers.js";

beforeAll(async () => {
  await runMigrations();
});
beforeEach(async () => {
  await truncateAll();
});
afterAll(async () => {
  await pool.end();
});

type Session = { cookie: string; csrf: string };

async function sessionFor(tenantId: string | null, role: TenantRole | null, superAdmin = false) {
  const { user, password } = await createAdminUser({
    name: "Jane Admin",
    isSuperAdmin: superAdmin,
  });
  if (tenantId && role) await addMember(tenantId, user.id, role);
  return { user, ...(await loginAs(app, user.email, password)) };
}

const call = (s: Session, method: string, path: string) =>
  jsonRequest(app, method, path, undefined, { cookie: s.cookie, "x-csrf-token": s.csrf });

async function setup() {
  const tenant = await createTenant();
  const { application } = await createApplication(tenant.id, { kind: "agent", name: "Refunder" });
  const { resource } = await createResourceWithScopes(tenant.id, "https://api.acme.io/payments", [
    "payments:read",
  ]);
  const make = (over: Partial<typeof approvalRequests.$inferInsert> = {}) =>
    createApprovalRequest(tenant.id, application.id, resource.id, over);
  const base = `/api/tenants/${tenant.id}/approvals`;
  return { tenant, application, resource, make, base };
}

const past = () => new Date(Date.now() - 1000);
const agoMs = (ms: number) => new Date(Date.now() - ms);

describe("approvals management", () => {
  it("approve records the decider; approve twice → 409 approval_already_decided", async () => {
    const s = await setup();
    const admin = await sessionFor(s.tenant.id, "admin");
    const row = await s.make({ taskId: "run-1", actorHint: "alice" });

    const res = await call(admin, "POST", `${s.base}/${row.id}/approve`);
    expect(res.status).toBe(200);
    const dto = await res.json();
    expect(dto).toMatchObject({
      id: row.id,
      applicationId: s.application.id,
      applicationName: "Refunder",
      clientId: s.application.clientId,
      status: "approved",
      taskId: "run-1",
      actorHint: "alice",
      decidedBy: { kind: "user", label: "Jane Admin" },
      decidedAt: expect.any(String),
    });
    const [stored] = await db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.id, row.id));
    expect(stored.decidedBy).toBe(admin.user.id);

    for (const action of ["approve", "deny"]) {
      const again = await call(admin, "POST", `${s.base}/${row.id}/${action}`);
      expect(again.status).toBe(409);
      expect((await again.json()).error).toBe("approval_already_decided");
    }
  });

  it("deny; an expired approval → 409 approval_expired", async () => {
    const s = await setup();
    const admin = await sessionFor(s.tenant.id, "admin");
    const row = await s.make();
    const denied = await call(admin, "POST", `${s.base}/${row.id}/deny`);
    expect((await denied.json()).status).toBe("denied");

    for (const over of [{ expiresAt: past() }, { status: "expired" as const, expiresAt: past() }]) {
      const dead = await s.make(over);
      const res = await call(admin, "POST", `${s.base}/${dead.id}/approve`);
      expect(res.status).toBe(409);
      expect((await res.json()).error).toBe("approval_expired");
    }
  });

  it("auditor lists but cannot decide; a super-admin can", async () => {
    const s = await setup();
    const row = await s.make();
    const auditor = await sessionFor(s.tenant.id, "auditor");
    expect((await call(auditor, "GET", s.base)).status).toBe(200);
    const forbidden = await call(auditor, "POST", `${s.base}/${row.id}/approve`);
    expect(forbidden.status).toBe(403);

    const superAdmin = await sessionFor(null, null, true);
    const res = await call(superAdmin, "POST", `${s.base}/${row.id}/deny`);
    expect(res.status).toBe(200);
    expect((await res.json()).decidedBy).toEqual({ kind: "user", label: "Jane Admin" });
  });

  it("non-member → 404 on list and approve; another tenant's id → 404", async () => {
    const s = await setup();
    const row = await s.make();
    const outsider = await sessionFor(null, null);
    expect((await call(outsider, "GET", s.base)).status).toBe(404);
    expect((await call(outsider, "POST", `${s.base}/${row.id}/approve`)).status).toBe(404);

    const other = await setup();
    const otherAdmin = await sessionFor(other.tenant.id, "admin");
    const cross = await call(otherAdmin, "POST", `${other.base}/${row.id}/approve`);
    expect(cross.status).toBe(404);
    expect((await cross.json()).error).toBe("approval_not_found");
    const bad = await call(otherAdmin, "POST", `${other.base}/not-a-uuid/approve`);
    expect(bad.status).toBe(404);
    const [stored] = await db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.id, row.id));
    expect(stored.status).toBe("pending");
  });

  it("pending excludes rows past expires_at; resolved includes expired; counts match", async () => {
    const s = await setup();
    const admin = await sessionFor(s.tenant.id, "auditor");
    const live = await s.make({ createdAt: agoMs(60_000) });
    await s.make({ expiresAt: past() });
    const expired = await s.make({ status: "expired", expiresAt: past() });
    const approved = await s.make({
      status: "approved",
      createdAt: agoMs(120_000),
      decidedAt: agoMs(60_000),
    });
    const denied = await s.make({
      status: "denied",
      createdAt: agoMs(180_000),
      decidedAt: agoMs(60_000),
    });
    // Decided outside the 24 h window: not counted today.
    await s.make({ status: "approved", decidedAt: agoMs(25 * 3600_000) });
    // Another tenant's rows never show up.
    const other = await setup();
    await other.make();

    const pending = await (await call(admin, "GET", s.base)).json();
    expect(pending.items.map((i: { id: string }) => i.id)).toEqual([live.id]);
    expect(pending.counts).toEqual({
      pending: 1,
      oldestPendingAt: live.createdAt.toISOString(),
      approvedToday: 1,
      deniedToday: 1,
      medianWaitSeconds: 90,
      rules: 0,
    });
    expect(pending.nextCursor).toBeNull();

    const resolved = await (await call(admin, "GET", `${s.base}?status=resolved`)).json();
    const ids = resolved.items.map((i: { id: string }) => i.id);
    expect(ids).toHaveLength(4);
    expect(ids).toEqual(expect.arrayContaining([expired.id, approved.id, denied.id]));
    expect(resolved.items.find((i: { id: string }) => i.id === expired.id).decidedBy).toBeNull();
  });

  it("cursor returns the next page without overlap", async () => {
    const s = await setup();
    const admin = await sessionFor(s.tenant.id, "auditor");
    const created = [];
    for (let i = 0; i < 5; i++) created.push(await s.make());

    const p1 = await (await call(admin, "GET", `${s.base}?limit=2`)).json();
    const p2 = await (
      await call(admin, "GET", `${s.base}?limit=2&cursor=${encodeURIComponent(p1.nextCursor)}`)
    ).json();
    const p3 = await (
      await call(admin, "GET", `${s.base}?limit=2&cursor=${encodeURIComponent(p2.nextCursor)}`)
    ).json();
    const ids = [...p1.items, ...p2.items, ...p3.items].map((i: { id: string }) => i.id);
    expect(new Set(ids).size).toBe(5);
    expect(ids.sort()).toEqual(created.map((r) => r.id).sort());
    expect(p3.nextCursor).toBeNull();

    const bad = await call(admin, "GET", `${s.base}?cursor=garbage`);
    expect(bad.status).toBe(400);
  });
});
