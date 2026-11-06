// Integration test: real Postgres through the full app.
import { pool, runMigrations } from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import {
  addMember,
  createAdminUser,
  createApprovalRule,
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

async function sessionFor(tenantId: string, role: TenantRole) {
  const { user, password } = await createAdminUser();
  await addMember(tenantId, user.id, role);
  return { user, ...(await loginAs(app, user.email, password)) };
}

const call = (s: Session, method: string, path: string, body?: unknown) =>
  jsonRequest(app, method, path, body, { cookie: s.cookie, "x-csrf-token": s.csrf });

async function setup() {
  const tenant = await createTenant();
  const { resource, scopes } = await createResourceWithScopes(
    tenant.id,
    "https://api.acme.io/payments",
    ["payments:write"],
    { name: "Payments" },
  );
  return { tenant, resource, scope: scopes[0], base: `/api/tenants/${tenant.id}/approval-rules` };
}

describe("approval rules management", () => {
  it("admin creates, lists and deletes a rule", async () => {
    const s = await setup();
    const admin = await sessionFor(s.tenant.id, "admin");
    const condition = { task_id_prefix: "refund-", max_scopes: 2 };
    const res = await call(admin, "POST", s.base, { scopeId: s.scope.id, condition });
    expect(res.status).toBe(201);
    const dto = await res.json();
    expect(dto).toEqual({
      id: expect.any(String),
      scopeId: s.scope.id,
      scopeName: "payments:write",
      resourceName: "Payments",
      condition,
      action: "auto_approve",
      createdBy: admin.user.id,
      createdAt: expect.any(String),
    });

    const list = await (await call(admin, "GET", s.base)).json();
    expect(list).toEqual({ items: [dto] });

    expect((await call(admin, "DELETE", `${s.base}/${dto.id}`)).status).toBe(204);
    expect((await (await call(admin, "GET", s.base)).json()).items).toEqual([]);
  });

  it("condition defaults to {}; unknown condition keys → 400 validation_error", async () => {
    const s = await setup();
    const admin = await sessionFor(s.tenant.id, "admin");
    const res = await call(admin, "POST", s.base, { scopeId: s.scope.id });
    expect((await res.json()).condition).toEqual({});
    const bad = await call(admin, "POST", s.base, {
      scopeId: s.scope.id,
      condition: { amount_lt: 20 },
    });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("validation_error");
  });

  it("auditor list → 200, create/delete → 403", async () => {
    const s = await setup();
    const rule = await createApprovalRule(s.tenant.id, s.scope.id);
    const auditor = await sessionFor(s.tenant.id, "auditor");
    expect((await call(auditor, "GET", s.base)).status).toBe(200);
    expect((await call(auditor, "POST", s.base, { scopeId: s.scope.id })).status).toBe(403);
    expect((await call(auditor, "DELETE", `${s.base}/${rule.id}`)).status).toBe(403);
  });

  it("scope from another tenant → 400 invalid_scope_ids", async () => {
    const s = await setup();
    const other = await setup();
    const admin = await sessionFor(s.tenant.id, "admin");
    const res = await call(admin, "POST", s.base, { scopeId: other.scope.id });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_scope_ids");
  });

  it("rule of another tenant → 404 on delete; malformed id → 404", async () => {
    const s = await setup();
    const other = await setup();
    const foreign = await createApprovalRule(other.tenant.id, other.scope.id);
    const admin = await sessionFor(s.tenant.id, "admin");
    for (const id of [foreign.id, "not-a-uuid"]) {
      const res = await call(admin, "DELETE", `${s.base}/${id}`);
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe("approval_rule_not_found");
    }
    // The foreign rule is untouched.
    const otherAdmin = await sessionFor(other.tenant.id, "admin");
    expect((await (await call(otherAdmin, "GET", other.base)).json()).items).toHaveLength(1);
  });

  it("duplicate (scope, condition) → 409 approval_rule_exists, key order ignored", async () => {
    const s = await setup();
    const admin = await sessionFor(s.tenant.id, "admin");
    const first = await call(admin, "POST", s.base, {
      scopeId: s.scope.id,
      condition: { max_scopes: 1, task_id_prefix: "a" },
    });
    expect(first.status).toBe(201);
    const dup = await call(admin, "POST", s.base, {
      scopeId: s.scope.id,
      condition: { task_id_prefix: "a", max_scopes: 1 },
    });
    expect(dup.status).toBe(409);
    expect((await dup.json()).error).toBe("approval_rule_exists");
    // A different condition on the same scope is fine.
    const other = await call(admin, "POST", s.base, { scopeId: s.scope.id, condition: {} });
    expect(other.status).toBe(201);
  });
});
