import { approvalsQuerySchema } from "@handsal/shared";
import { Hono } from "hono";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import { decideApproval, listApprovals } from "../../services/approval.service.js";

export const approvalRoutes = new Hono<AdminEnv>();

approvalRoutes.get("/:tenantId/approvals", requireTenantAccess("auditor"), async (c) => {
  const query = approvalsQuerySchema.parse(c.req.query());
  return c.json(await listApprovals(c.req.param("tenantId"), query));
});

for (const [action, decision] of [
  ["approve", "approved"],
  ["deny", "denied"],
] as const) {
  approvalRoutes.post(
    `/:tenantId/approvals/:approvalId/${action}`,
    requireTenantAccess("admin"),
    async (c) =>
      c.json(
        await decideApproval(
          c.req.param("tenantId"),
          c.req.param("approvalId"),
          decision,
          c.var.actor,
        ),
      ),
  );
}
