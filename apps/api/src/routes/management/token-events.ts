import { applications, db } from "@handsal/db";
import { tokenEventsQuerySchema } from "@handsal/shared";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { ApiError } from "../../middleware/error-handler.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import { getTokenStats, listTokenEvents } from "../../services/token-event.service.js";

export const tokenEventRoutes = new Hono<AdminEnv>();

// `q` matches application_client_id / jti prefix only; listTokenEvents has no application-name filter.
tokenEventRoutes.get("/:tenantId/token-events", requireTenantAccess("auditor"), async (c) => {
  const query = tokenEventsQuerySchema.parse(c.req.query());
  return c.json(await listTokenEvents(c.req.param("tenantId"), query));
});

tokenEventRoutes.get("/:tenantId/token-events/stats", requireTenantAccess("auditor"), async (c) =>
  c.json(await getTokenStats(c.req.param("tenantId"))),
);

tokenEventRoutes.get(
  "/:tenantId/applications/:appId/token-events",
  requireTenantAccess("auditor"),
  async (c) => {
    const tenantId = c.req.param("tenantId");
    const appId = c.req.param("appId");
    const { limit } = tokenEventsQuerySchema.pick({ limit: true }).parse(c.req.query());
    const notFound = () => new ApiError(404, "application_not_found", "Application not found");
    if (!z.uuid().safeParse(appId).success) throw notFound();
    const [app] = await db
      .select({ id: applications.id })
      .from(applications)
      .where(and(eq(applications.id, appId), eq(applications.tenantId, tenantId)));
    if (!app) throw notFound();

    const { items } = await listTokenEvents(tenantId, { limit, applicationId: appId });
    return c.json({ items });
  },
);
