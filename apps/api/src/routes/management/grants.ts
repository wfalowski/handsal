import { grantsReplaceSchema } from "@handsal/shared";
import { type Context, Hono } from "hono";
import { z } from "zod";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { ApiError } from "../../middleware/error-handler.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import { getApplication } from "../../services/application.service.js";
import { getGrants, replaceGrants } from "../../services/grant.service.js";

/** `:appId` from the path; a non-UUID is indistinguishable from a missing application (404). */
export function appIdParam(c: Context<AdminEnv>): string {
  const appId = c.req.param("appId");
  if (!z.uuid().safeParse(appId).success) {
    throw new ApiError(404, "application_not_found", "Application not found");
  }
  return appId as string;
}

// Mounted under /api/tenants via ./applications.ts.
export const grantRoutes = new Hono<AdminEnv>();

grantRoutes.get(
  "/:tenantId/applications/:appId/grants",
  requireTenantAccess("auditor"),
  async (c) => {
    const tenantId = c.req.param("tenantId");
    const appId = appIdParam(c);
    await getApplication(tenantId, appId); // 404 for an unknown app / an app of another tenant
    return c.json({ grants: await getGrants(tenantId, appId) });
  },
);

grantRoutes.put(
  "/:tenantId/applications/:appId/grants",
  requireTenantAccess("admin"),
  async (c) => {
    const appId = appIdParam(c);
    const { scopeIds } = grantsReplaceSchema.parse(await c.req.json().catch(() => ({})));
    return c.json({ grants: await replaceGrants(c.req.param("tenantId"), appId, scopeIds) });
  },
);
