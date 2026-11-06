import { tenantCreateSchema, tenantUpdateSchema } from "@handsal/shared";
import { Hono } from "hono";
import { z } from "zod";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import {
  createTenant,
  deleteTenant,
  getTenantDetail,
  listTenantsWithStats,
  revokeAllTenantTokens,
  setTenantStatus,
  updateTenant,
} from "../../services/tenant.service.js";

const deleteTenantSchema = z.object({ confirmSlug: z.string() });

// Mounted at /api/tenants. `requireTenantAccess` sits on each `:tenantId` route (not router-wide).
export const tenantRoutes = new Hono<AdminEnv>();

tenantRoutes.get("/", async (c) => {
  const actor = c.var.actor;
  return c.json(
    await listTenantsWithStats(
      actor.kind === "user" && !actor.isSuperAdmin ? actor.userId : undefined,
    ),
  );
});

tenantRoutes.post("/", async (c) => {
  const input = tenantCreateSchema.parse(await c.req.json().catch(() => ({})));
  const actor = c.var.actor;
  return c.json(await createTenant(input, actor.kind === "user" ? actor.userId : undefined), 201);
});

tenantRoutes.get("/:tenantId", requireTenantAccess("auditor"), async (c) => {
  const tenant = await getTenantDetail(c.req.param("tenantId"));
  return c.json({ ...tenant, role: c.var.tenantRole });
});

tenantRoutes.patch("/:tenantId", requireTenantAccess("admin"), async (c) => {
  const input = tenantUpdateSchema.parse(await c.req.json().catch(() => ({})));
  return c.json(await updateTenant(c.req.param("tenantId"), input));
});

tenantRoutes.post("/:tenantId/pause", requireTenantAccess("owner"), async (c) => {
  return c.json(await setTenantStatus(c.req.param("tenantId"), "paused"));
});

tenantRoutes.post("/:tenantId/resume", requireTenantAccess("owner"), async (c) => {
  return c.json(await setTenantStatus(c.req.param("tenantId"), "active"));
});

tenantRoutes.post("/:tenantId/revoke-all-tokens", requireTenantAccess("owner"), async (c) => {
  return c.json(await revokeAllTenantTokens(c.req.param("tenantId")));
});

tenantRoutes.delete("/:tenantId", requireTenantAccess("owner"), async (c) => {
  const { confirmSlug } = deleteTenantSchema.parse(await c.req.json().catch(() => ({})));
  await deleteTenant(c.req.param("tenantId"), confirmSlug);
  return c.body(null, 204);
});
