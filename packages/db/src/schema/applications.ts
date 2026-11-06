import {
  index,
  integer,
  pgEnum,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { adminUsers } from "./admin-users.js";
import { tenants } from "./tenants.js";

export const applicationKind = pgEnum("application_kind", ["service", "agent"]);
export const tokenEndpointAuthMethod = pgEnum("token_endpoint_auth_method", [
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
]);
export const applicationStatus = pgEnum("application_status", ["active", "disabled"]);

export const applications = pgTable(
  "applications",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    description: text("description"),
    kind: applicationKind("kind").notNull().default("service"),
    clientId: varchar("client_id", { length: 32 }).notNull().unique(),
    clientSecretHash: varchar("client_secret_hash", { length: 512 }),
    previousSecretHash: varchar("previous_secret_hash", { length: 512 }),
    previousSecretExpiresAt: timestamp("previous_secret_expires_at", { withTimezone: true }),
    secretRotatedAt: timestamp("secret_rotated_at", { withTimezone: true }),
    tokenEndpointAuthMethod: tokenEndpointAuthMethod("token_endpoint_auth_method")
      .notNull()
      .default("client_secret_basic"),
    tokenTtlSeconds: integer("token_ttl_seconds"),
    status: applicationStatus("status").notNull().default("active"),
    tokensNotBefore: timestamp("tokens_not_before", { withTimezone: true }),
    lastTokenAt: timestamp("last_token_at", { withTimezone: true }),
    createdBy: uuid("created_by").references(() => adminUsers.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    index("idx_applications_tenant_id").on(t.tenantId),
    unique("uq_applications_tenant_id_name").on(t.tenantId, t.name),
    // Composite unique so application_grants can reference (tenant_id, id) and enforce same-tenant linkage.
    unique("uq_applications_tenant_id_id").on(t.tenantId, t.id),
  ],
);
