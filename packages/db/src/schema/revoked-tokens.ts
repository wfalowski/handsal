import { index, pgTable, timestamp, uuid, varchar } from "drizzle-orm/pg-core";
import { tenants } from "./tenants.js";

export const revokedTokens = pgTable(
  "revoked_tokens",
  {
    jti: varchar("jti", { length: 64 }).primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (t) => [
    index("idx_revoked_tokens_expires_at").on(t.expiresAt),
    index("idx_revoked_tokens_tenant_id").on(t.tenantId),
  ],
);
