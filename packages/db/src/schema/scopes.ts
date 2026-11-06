import {
  foreignKey,
  pgEnum,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { resources } from "./resources.js";
import { tenants } from "./tenants.js";

export const agentPolicy = pgEnum("agent_policy", ["auto", "approval", "never"]);

export const scopes = pgTable(
  "scopes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    resourceId: uuid("resource_id").notNull(),
    name: varchar("name", { length: 128 }).notNull(),
    description: text("description"),
    agentPolicy: agentPolicy("agent_policy").notNull().default("auto"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    unique("uq_scopes_resource_id_name").on(t.resourceId, t.name),
    // Composite unique so application_grants can reference (tenant_id, id) and enforce same-tenant linkage.
    unique("uq_scopes_tenant_id_id").on(t.tenantId, t.id),
    // Same-tenant invariant: a scope can only belong to a resource of its own tenant.
    foreignKey({
      columns: [t.tenantId, t.resourceId],
      foreignColumns: [resources.tenantId, resources.id],
      name: "fk_scopes_resource",
    }).onDelete("cascade"),
  ],
);
