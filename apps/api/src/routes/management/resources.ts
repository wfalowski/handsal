import { resourceCreateSchema, resourceUpdateSchema } from "@handsal/shared";
import { Hono } from "hono";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import {
  createResource,
  deleteResource,
  getResourceDetail,
  listResources,
  updateResource,
} from "../../services/resource.service.js";
import { scopeRoutes } from "./scopes.js";

// Mounted at /api/tenants.
export const resourceRoutes = new Hono<AdminEnv>();

resourceRoutes.get("/:tenantId/resources", requireTenantAccess("auditor"), async (c) =>
  c.json(await listResources(c.req.param("tenantId"))),
);

resourceRoutes.post("/:tenantId/resources", requireTenantAccess("admin"), async (c) => {
  const input = resourceCreateSchema.parse(await c.req.json().catch(() => ({})));
  return c.json(await createResource(c.req.param("tenantId"), input), 201);
});

resourceRoutes.get("/:tenantId/resources/:resourceId", requireTenantAccess("auditor"), async (c) =>
  c.json(await getResourceDetail(c.req.param("tenantId"), c.req.param("resourceId"))),
);

resourceRoutes.patch(
  "/:tenantId/resources/:resourceId",
  requireTenantAccess("admin"),
  async (c) => {
    const input = resourceUpdateSchema.parse(await c.req.json().catch(() => ({})));
    return c.json(await updateResource(c.req.param("tenantId"), c.req.param("resourceId"), input));
  },
);

resourceRoutes.delete(
  "/:tenantId/resources/:resourceId",
  requireTenantAccess("admin"),
  async (c) => {
    await deleteResource(c.req.param("tenantId"), c.req.param("resourceId"));
    return c.body(null, 204);
  },
);

resourceRoutes.route("/:tenantId/resources/:resourceId/scopes", scopeRoutes);
