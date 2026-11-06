import { sql } from "drizzle-orm";
import { foreignKey, index, jsonb, pgEnum, pgTable, timestamp, uuid } from "drizzle-orm/pg-core";
import { adminUsers } from "./admin-users.js";
import { scopes } from "./scopes.js";
import { tenants } from "./tenants.js";

export const approvalRuleAction = pgEnum("approval_rule_action", ["auto_approve"]);

export const approvalRules = pgTable(
  "approval_rules",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    scopeId: uuid("scope_id").notNull(),
    // All-of semantics; `{}` matches every request. Validated by approvalConditionSchema.
    condition: jsonb("condition")
      .$type<{ application_ids?: string[]; task_id_prefix?: string; max_scopes?: number }>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    action: approvalRuleAction("action").notNull().default("auto_approve"),
    createdBy: uuid("created_by").references(() => adminUsers.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    index("idx_approval_rules_tenant_scope").on(t.tenantId, t.scopeId),
    // Same-tenant invariant plus cascade on scope delete.
    foreignKey({
      columns: [t.tenantId, t.scopeId],
      foreignColumns: [scopes.tenantId, scopes.id],
      name: "fk_approval_rules_scope",
    }).onDelete("cascade"),
  ],
);
