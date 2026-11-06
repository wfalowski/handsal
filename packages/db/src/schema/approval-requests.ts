import { sql } from "drizzle-orm";
import {
  foreignKey,
  index,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { adminUsers } from "./admin-users.js";
import { applications } from "./applications.js";
import { approvalRules } from "./approval-rules.js";
import { resources } from "./resources.js";
import { tenants } from "./tenants.js";

export const approvalStatus = pgEnum("approval_status", [
  "pending",
  "approved",
  "denied",
  "expired",
]);

export const approvalRequests = pgTable(
  "approval_requests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    applicationId: uuid("application_id").notNull(),
    resourceId: uuid("resource_id").notNull(),
    // Denormalised: survives a resource rename.
    audience: varchar("audience", { length: 512 }).notNull(),
    // Scope names, not ids.
    scopes: text("scopes").array().notNull().default(sql`'{}'::text[]`),
    actorHint: varchar("actor_hint", { length: 255 }),
    taskId: varchar("task_id", { length: 128 }),
    justification: text("justification"),
    status: approvalStatus("status").notNull().default("pending"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    // The human who decided; null for expiry and ADMIN_API_KEY actors.
    decidedBy: uuid("decided_by").references(() => adminUsers.id, { onDelete: "set null" }),
    // The auto-approve rule that decided; null for human decisions and expiry.
    decidedByRuleId: uuid("decided_by_rule_id").references(() => approvalRules.id, {
      onDelete: "set null",
    }),
    // Who decided, as shown at decision time: survives deletion of the user or rule.
    decidedByLabel: text("decided_by_label"),
    decidedAt: timestamp("decided_at", { withTimezone: true }),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    index("idx_approval_requests_tenant_status").on(t.tenantId, t.status, t.createdAt.desc()),
    index("idx_approval_requests_application_id").on(t.applicationId),
    index("idx_approval_requests_tenant_decided_at").on(t.tenantId, t.decidedAt),
    // Same-tenant invariants plus cascade on application / resource delete.
    foreignKey({
      columns: [t.tenantId, t.applicationId],
      foreignColumns: [applications.tenantId, applications.id],
      name: "fk_approval_requests_application",
    }).onDelete("cascade"),
    foreignKey({
      columns: [t.tenantId, t.resourceId],
      foreignColumns: [resources.tenantId, resources.id],
      name: "fk_approval_requests_resource",
    }).onDelete("cascade"),
  ],
);
