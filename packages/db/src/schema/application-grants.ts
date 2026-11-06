import { foreignKey, index, pgTable, primaryKey, uuid } from "drizzle-orm/pg-core";
import { applications } from "./applications.js";
import { scopes } from "./scopes.js";
import { tenants } from "./tenants.js";

export const applicationGrants = pgTable(
  "application_grants",
  {
    // Denormalized tenant id: present so the composite foreign keys below can
    // structurally guarantee that the application and the scope share a tenant.
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    applicationId: uuid("application_id").notNull(),
    scopeId: uuid("scope_id").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.applicationId, t.scopeId] }),
    index("idx_application_grants_scope_id").on(t.scopeId),
    index("idx_application_grants_tenant_id").on(t.tenantId),
    foreignKey({
      columns: [t.tenantId, t.applicationId],
      foreignColumns: [applications.tenantId, applications.id],
      name: "fk_application_grants_application",
    }).onDelete("cascade"),
    foreignKey({
      columns: [t.tenantId, t.scopeId],
      foreignColumns: [scopes.tenantId, scopes.id],
      name: "fk_application_grants_scope",
    }).onDelete("cascade"),
  ],
);
