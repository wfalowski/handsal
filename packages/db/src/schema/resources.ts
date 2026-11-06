import { integer, pgEnum, pgTable, timestamp, unique, uuid, varchar } from "drizzle-orm/pg-core";
import { tenants } from "./tenants.js";

export const resourceKind = pgEnum("resource_kind", ["api", "mcp"]);
export const resourceStatus = pgEnum("resource_status", ["active", "disabled"]);

export const resources = pgTable(
  "resources",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    kind: resourceKind("kind").notNull().default("api"),
    audience: varchar("audience", { length: 512 }).notNull(),
    tokenTtlSeconds: integer("token_ttl_seconds"),
    status: resourceStatus("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    unique("uq_resources_tenant_id_audience").on(t.tenantId, t.audience),
    unique("uq_resources_tenant_id_name").on(t.tenantId, t.name),
    // Composite unique so scopes can reference (tenant_id, id) and enforce same-tenant linkage.
    unique("uq_resources_tenant_id_id").on(t.tenantId, t.id),
  ],
);
