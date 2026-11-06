import {
  boolean,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

export const tenantStatus = pgEnum("tenant_status", ["active", "paused"]);

export const tenants = pgTable("tenants", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: varchar("name", { length: 255 }).notNull(),
  slug: varchar("slug", { length: 63 }).notNull().unique(),
  status: tenantStatus("status").notNull().default("active"),
  defaultTokenTtlSeconds: integer("default_token_ttl_seconds").notNull().default(3600),
  introspectionEnabled: boolean("introspection_enabled").notNull().default(true),
  // null = manual rotation only
  keyRotationDays: integer("key_rotation_days"),
  tokensNotBefore: timestamp("tokens_not_before", { withTimezone: true }),
  // Trusted external IdP for token-exchange subject tokens; null = none.
  // shortcut: one external issuer per tenant; promote to a trusted_issuers table when a tenant needs two
  externalIdp: jsonb("external_idp").$type<{ issuer: string; jwksUri: string; audience: string }>(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
});
