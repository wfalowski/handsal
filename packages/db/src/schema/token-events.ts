import { sql } from "drizzle-orm";
import {
  bigserial,
  index,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { tenants } from "./tenants.js";

export const tokenEventOutcome = pgEnum("token_event_outcome", ["issued", "denied", "revoked"]);

export const tokenEvents = pgTable(
  "token_events",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    // No FKs on application_id / resource_id: history must survive their deletion.
    applicationId: uuid("application_id"),
    applicationClientId: varchar("application_client_id", { length: 32 }),
    resourceId: uuid("resource_id"),
    audience: varchar("audience", { length: 512 }),
    outcome: tokenEventOutcome("outcome").notNull(),
    reason: varchar("reason", { length: 64 }),
    scopes: text("scopes").array().notNull().default(sql`'{}'::text[]`),
    jti: varchar("jti", { length: 64 }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    sourceIp: varchar("source_ip", { length: 45 }),
    taskId: varchar("task_id", { length: 128 }),
    // Delegating actor (`act.sub`); written by token exchange (Task 6.4).
    actorSub: varchar("actor_sub", { length: 255 }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("idx_token_events_tenant_id_created_at").on(t.tenantId, t.createdAt.desc()),
    index("idx_token_events_jti").on(t.jti),
    index("idx_token_events_application_id_created_at").on(t.applicationId, t.createdAt.desc()),
    index("idx_token_events_task_id").on(t.taskId),
  ],
);
