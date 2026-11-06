// Integration test: real Postgres.
import { db, revokedTokens, runMigrations } from "@handsal/db";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createTenant, truncateAll } from "../test/factories.js";
import { purgeExpiredRevocations, revokeAllTenantTokens } from "./revocation.service.js";
import { getTenantById } from "./tenant.service.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("revocation.service", () => {
  it("revokeAllTenantTokens sets tokens_not_before to now", async () => {
    const tenant = await createTenant();
    const before = Date.now();
    await revokeAllTenantTokens(tenant.id);
    const mark = (await getTenantById(tenant.id))?.tokensNotBefore?.getTime() ?? 0;
    expect(mark).toBeGreaterThanOrEqual(before);
    expect(mark).toBeLessThanOrEqual(Date.now());
  });

  it("purgeExpiredRevocations deletes only expired rows", async () => {
    const tenant = await createTenant();
    await db.insert(revokedTokens).values([
      { jti: "expired", tenantId: tenant.id, expiresAt: new Date(Date.now() - 60_000) },
      { jti: "live", tenantId: tenant.id, expiresAt: new Date(Date.now() + 60_000) },
    ]);
    expect(await purgeExpiredRevocations()).toBe(1);
    const rows = await db.select({ jti: revokedTokens.jti }).from(revokedTokens);
    expect(rows).toEqual([{ jti: "live" }]);
  });
});
