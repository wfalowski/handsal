import { scopeCreateSchema, scopeDtoSchema, scopeUpdateSchema } from "@handsal/shared";
import { type Context, Hono } from "hono";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import { createScope, deleteScope, listScopes, updateScope } from "../../services/scope.service.js";

const createSchema = scopeCreateSchema;
const updateSchema = scopeUpdateSchema;

// Mounted at /:tenantId/resources/:resourceId/scopes inside ./resources.ts.
export const scopeRoutes = new Hono<AdminEnv>();

const ids = (c: Context<AdminEnv>) =>
  [c.req.param("tenantId") ?? "", c.req.param("resourceId") ?? ""] as const;

scopeRoutes.get("/", requireTenantAccess("auditor"), async (c) => {
  const [tenantId, resourceId] = ids(c);
  return c.json(await listScopes(tenantId, resourceId));
});

scopeRoutes.post("/", requireTenantAccess("admin"), async (c) => {
  const [tenantId, resourceId] = ids(c);
  const input = createSchema.parse(await c.req.json().catch(() => ({})));
  return c.json(await createScope(tenantId, resourceId, input), 201);
});

scopeRoutes.patch("/:scopeId", requireTenantAccess("admin"), async (c) => {
  const [tenantId, resourceId] = ids(c);
  const input = updateSchema.parse(await c.req.json().catch(() => ({})));
  return c.json(await updateScope(tenantId, resourceId, c.req.param("scopeId"), input));
});

scopeRoutes.delete("/:scopeId", requireTenantAccess("admin"), async (c) => {
  const [tenantId, resourceId] = ids(c);
  await deleteScope(tenantId, resourceId, c.req.param("scopeId"));
  return c.body(null, 204);
});
