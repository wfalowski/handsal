import { approvalRuleCreateSchema } from "@handsal/shared";
import { Hono } from "hono";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import {
  createApprovalRule,
  deleteApprovalRule,
  listApprovalRules,
} from "../../services/approval-rule.service.js";

// Mounted at /api/tenants. No PATCH: delete and recreate.
export const approvalRuleRoutes = new Hono<AdminEnv>();

approvalRuleRoutes.get("/:tenantId/approval-rules", requireTenantAccess("auditor"), async (c) =>
  c.json({ items: await listApprovalRules(c.req.param("tenantId")) }),
);

approvalRuleRoutes.post("/:tenantId/approval-rules", requireTenantAccess("admin"), async (c) => {
  const input = approvalRuleCreateSchema.parse(await c.req.json().catch(() => ({})));
  return c.json(await createApprovalRule(c.req.param("tenantId"), input, c.var.actor), 201);
});

approvalRuleRoutes.delete(
  "/:tenantId/approval-rules/:ruleId",
  requireTenantAccess("admin"),
  async (c) => {
    await deleteApprovalRule(c.req.param("tenantId"), c.req.param("ruleId"));
    return c.body(null, 204);
  },
);
