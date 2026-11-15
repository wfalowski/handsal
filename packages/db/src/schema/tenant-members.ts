import { index, pgEnum, pgTable, primaryKey, timestamp, uuid } from "drizzle-orm/pg-core";
import { adminUsers } from "./admin-users.js";
import { tenants } from "./tenants.js";

export const tenantRole = pgEnum("tenant_role", ["owner", "admin", "auditor"]);
// Not `tenant_status`: that name belongs to `tenants.status`.
export const tenantMemberStatus = pgEnum("tenant_member_status", ["active", "pending"]);

export const tenantMembers = pgTable(
  "tenant_members",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    adminUserId: uuid("admin_user_id")
      .notNull()
      .references(() => adminUsers.id, { onDelete: "cascade" }),
    role: tenantRole("role").notNull(),
    // Only `active` grants access; `pending` is an invitation not yet accepted.
    status: tenantMemberStatus("status").notNull().default("active"),
    // `set null`: deleting the inviter must not delete someone else's membership.
    invitedBy: uuid("invited_by").references(() => adminUsers.id, { onDelete: "set null" }),
    invitedAt: timestamp("invited_at", { withTimezone: true }),
  },
  (t) => [
    primaryKey({ columns: [t.tenantId, t.adminUserId] }),
    index("idx_tenant_members_admin_user_id").on(t.adminUserId),
  ],
);
