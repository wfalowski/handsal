import { index, pgEnum, pgTable, primaryKey, uuid } from "drizzle-orm/pg-core";
import { adminUsers } from "./admin-users.js";
import { tenants } from "./tenants.js";

export const tenantRole = pgEnum("tenant_role", ["owner", "admin", "auditor"]);

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
  },
  (t) => [
    primaryKey({ columns: [t.tenantId, t.adminUserId] }),
    index("idx_tenant_members_admin_user_id").on(t.adminUserId),
  ],
);
