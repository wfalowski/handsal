import { memberCreateSchema, memberUpdateSchema } from "@handsal/shared";
import { Hono } from "hono";
import { z } from "zod";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { ApiError } from "../../middleware/error-handler.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import {
  addMember,
  listMembers,
  removeMember,
  updateMemberRole,
} from "../../services/member.service.js";

// Mounted at /api/tenants (next to tenantRoutes); every path starts with `/:tenantId/members`.
export const memberRoutes = new Hono<AdminEnv>();

function memberId(value: string): string {
  if (!z.uuid().safeParse(value).success) {
    throw new ApiError(404, "member_not_found", "Member not found");
  }
  return value;
}

memberRoutes.get("/:tenantId/members", requireTenantAccess("auditor"), async (c) => {
  return c.json(await listMembers(c.req.param("tenantId")));
});

memberRoutes.post("/:tenantId/members", requireTenantAccess("owner"), async (c) => {
  const input = memberCreateSchema.parse(await c.req.json().catch(() => ({})));
  return c.json(await addMember(c.req.param("tenantId"), input), 201);
});

memberRoutes.patch("/:tenantId/members/:adminUserId", requireTenantAccess("owner"), async (c) => {
  const adminUserId = memberId(c.req.param("adminUserId"));
  const { role } = memberUpdateSchema.parse(await c.req.json().catch(() => ({})));
  const actor = c.var.actor;
  const member = await updateMemberRole(c.req.param("tenantId"), adminUserId, role, actor.userId);
  return c.json(member);
});

memberRoutes.delete("/:tenantId/members/:adminUserId", requireTenantAccess("owner"), async (c) => {
  const adminUserId = memberId(c.req.param("adminUserId"));
  const actor = c.var.actor;
  await removeMember(c.req.param("tenantId"), adminUserId, actor.userId);
  return c.body(null, 204);
});
