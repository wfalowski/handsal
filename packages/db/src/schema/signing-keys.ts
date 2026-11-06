import { sql } from "drizzle-orm";
import {
  pgEnum,
  pgTable,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { tenants } from "./tenants.js";

export const signingKeyStatus = pgEnum("signing_key_status", ["active", "retiring", "retired"]);

export const signingKeys = pgTable(
  "signing_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    kid: varchar("kid", { length: 64 }).notNull().unique(),
    algorithm: varchar("algorithm", { length: 10 }).notNull().default("ES256"),
    publicKeyPem: text("public_key_pem").notNull(),
    privateKeyEnc: text("private_key_enc").notNull(), // AES-256-GCM encrypted PEM
    status: signingKeyStatus("status").notNull().default("active"),
    retiresAt: timestamp("retires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    unique("uq_signing_keys_tenant_id_id").on(t.tenantId, t.id),
    // At most one active (signing) key per tenant.
    uniqueIndex("uq_signing_keys_one_active_per_tenant")
      .on(t.tenantId)
      .where(sql`${t.status} = 'active'`),
  ],
);
