import { db, tenants } from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { eq } from "drizzle-orm";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";
import { getTenantRole } from "../services/admin-user.service.js";
import type { AdminEnv } from "./admin-auth.js";
import { ApiError } from "./error-handler.js";

const ROLE_RANK: Record<TenantRole, number> = { auditor: 0, admin: 1, owner: 2 };

const tenantNotFound = () => new ApiError(404, "tenant_not_found", "Tenant not found");

/**
 * Guards routes with `:tenantId`. Super-admins / API key act as `owner`; others need a
 * `tenant_members` row. Missing tenant and non-member both 404 (existence is not revealed);
 * a role below `minRole` is 403. Sets `c.var.tenantRole`. Runs after `adminAuth`.
 */
export function requireTenantAccess(minRole: TenantRole): MiddlewareHandler<AdminEnv> {
  return async (c, next) => {
    const tenantId = c.req.param("tenantId");
    if (!z.uuid().safeParse(tenantId).success) throw tenantNotFound();

    const actor = c.var.actor;
    let role: TenantRole | null;
    if (actor.isSuperAdmin) {
      const [tenant] = await db
        .select({ id: tenants.id })
        .from(tenants)
        .where(eq(tenants.id, tenantId as string))
        .limit(1);
      role = tenant ? "owner" : null;
    } else {
      // A membership row implies the tenant exists (FK, cascade on delete).
      role = await getTenantRole(actor.userId, tenantId as string);
    }
    if (!role) throw tenantNotFound();
    if (ROLE_RANK[role] < ROLE_RANK[minRole]) {
      throw new ApiError(403, "forbidden", `Requires the ${minRole} role on this tenant`);
    }

    c.set("tenantRole", role);
    await next();
  };
}
