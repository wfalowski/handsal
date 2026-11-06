import { randomUUID } from "node:crypto";
import { pool, runMigrations } from "@handsal/db";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { addMember, createAdminUser, createTenant, truncateAll } from "../test/factories.js";
import {
  type AdminEnv,
  createAdminAuth,
  createSessionToken,
  SESSION_COOKIE,
} from "./admin-auth.js";
import { errorHandler } from "./error-handler.js";
import { requireTenantAccess } from "./tenant-access.js";

const API_KEY = "k".repeat(40);

const probe = new Hono<AdminEnv>();
probe.use("*", createAdminAuth({ apiKey: API_KEY }));
probe.get("/api/tenants/:tenantId/probe", requireTenantAccess("admin"), (c) =>
  c.json({ role: c.var.tenantRole }),
);
probe.onError(errorHandler);

const asUser = (userId: string, tenantId: string) =>
  probe.request(`/api/tenants/${tenantId}/probe`, {
    headers: { cookie: `${SESSION_COOKIE}=${createSessionToken(userId)}` },
  });

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

describe('requireTenantAccess("admin")', () => {
  it("auditor → 403 forbidden", async () => {
    const tenant = await createTenant();
    const { user } = await createAdminUser();
    await addMember(tenant.id, user.id, "auditor");
    const res = await asUser(user.id, tenant.id);
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("forbidden");
  });

  it.each(["admin", "owner"] as const)("%s → 200 with tenantRole", async (role) => {
    const tenant = await createTenant();
    const { user } = await createAdminUser();
    await addMember(tenant.id, user.id, role);
    const res = await asUser(user.id, tenant.id);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ role });
  });

  it("non-member → 404, same as a missing tenant", async () => {
    const tenant = await createTenant();
    const other = await createTenant();
    const { user } = await createAdminUser();
    await addMember(other.id, user.id, "owner");

    for (const tenantId of [tenant.id, randomUUID(), "not-a-uuid"]) {
      const res = await asUser(user.id, tenantId);
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe("tenant_not_found");
    }
  });

  it("super-admin who is not a member → 200 as owner; missing tenant still 404", async () => {
    const tenant = await createTenant();
    const { user } = await createAdminUser({ isSuperAdmin: true });
    const res = await asUser(user.id, tenant.id);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ role: "owner" });
    expect((await asUser(user.id, randomUUID())).status).toBe(404);
  });

  it("API key → 200 as owner", async () => {
    const tenant = await createTenant();
    const res = await probe.request(`/api/tenants/${tenant.id}/probe`, {
      headers: { authorization: `Bearer ${API_KEY}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ role: "owner" });
  });
});
