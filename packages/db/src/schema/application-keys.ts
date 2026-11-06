import {
  foreignKey,
  index,
  pgEnum,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { applications } from "./applications.js";
import { tenants } from "./tenants.js";

export const applicationKeyStatus = pgEnum("application_key_status", ["active", "retiring"]);

export const applicationKeys = pgTable(
  "application_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    applicationId: uuid("application_id").notNull(),
    kid: varchar("kid", { length: 128 }).notNull(),
    algorithm: varchar("algorithm", { length: 10 }).notNull().default("ES256"),
    publicKeyPem: text("public_key_pem").notNull(), // SPKI PEM
    // Lowercase hex SHA-256 over the DER SPKI.
    fingerprintSha256: varchar("fingerprint_sha256", { length: 64 }).notNull(),
    status: applicationKeyStatus("status").notNull().default("active"),
    retiresAt: timestamp("retires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    unique("uq_application_keys_application_id_kid").on(t.applicationId, t.kid),
    // Blocks the same key registered twice under two kids.
    unique("uq_application_keys_application_id_fingerprint").on(
      t.applicationId,
      t.fingerprintSha256,
    ),
    index("idx_application_keys_application_id").on(t.applicationId),
    // Same-tenant invariant plus cascade on application delete.
    foreignKey({
      columns: [t.tenantId, t.applicationId],
      foreignColumns: [applications.tenantId, applications.id],
      name: "fk_application_keys_application",
    }).onDelete("cascade"),
  ],
);
