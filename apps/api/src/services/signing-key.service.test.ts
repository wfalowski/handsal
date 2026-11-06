// Integration test: real Postgres, no HTTP app.
import { applications, db, resources, runMigrations, signingKeys } from "@handsal/db";
import { eq, inArray, sql } from "drizzle-orm";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createTenant, truncateAll } from "../test/factories.js";
import { signAccessToken, verifyAccessToken } from "../utils/jwt.js";
import {
  autoRotateDueKeys,
  ensureActiveKey,
  getActiveKey,
  getJwks,
  listKeys,
  retireExpiredKeys,
  rotateKey,
} from "./signing-key.service.js";

const ISSUER = "https://test.example.com/t/acme";

function claims() {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, sub: "app_x", aud: "https://api", iat: now, exp: now + 300, jti: "j" };
}

async function statuses(tenantId: string) {
  return (await listKeys(tenantId)).map((k) => k.status).sort();
}

/** Seconds between now and the key's `retires_at`. */
async function graceOf(kid: string): Promise<number> {
  const [row] = await db
    .select({ s: sql<number>`extract(epoch from ${signingKeys.retiresAt} - now())::int` })
    .from(signingKeys)
    .where(eq(signingKeys.kid, kid));
  return Number(row.s);
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("ensureActiveKey", () => {
  it("creates one key and is idempotent", async () => {
    const tenant = await createTenant();
    const a = await ensureActiveKey(tenant.id);
    const b = await ensureActiveKey(tenant.id);
    expect(b.kid).toBe(a.kid);
    expect(a.kid).toMatch(/^k_\d{4}-\d{2}-\d{2}_[0-9a-f]{4}$/);
    expect(a.status).toBe("active");
    expect(a).not.toHaveProperty("privateKeyEnc");
    expect(await listKeys(tenant.id)).toHaveLength(1);
  });

  it("is race-safe under concurrent calls", async () => {
    const tenant = await createTenant();
    const keys = await Promise.all(Array.from({ length: 5 }, () => ensureActiveKey(tenant.id)));
    expect(new Set(keys.map((k) => k.kid)).size).toBe(1);
    expect(await listKeys(tenant.id)).toHaveLength(1);
  });

  it("stores the private key encrypted", async () => {
    const tenant = await createTenant();
    await ensureActiveKey(tenant.id);
    const [row] = await db.select().from(signingKeys).where(eq(signingKeys.tenantId, tenant.id));
    expect(row.privateKeyEnc).not.toContain("PRIVATE KEY");
    expect((await getActiveKey(tenant.id)).privateKeyPem).toContain("BEGIN PRIVATE KEY");
  });
});

describe("rotateKey", () => {
  it("leaves exactly one active and one retiring key and signs with the new one", async () => {
    const tenant = await createTenant();
    const old = await ensureActiveKey(tenant.id);
    const created = await rotateKey(tenant.id, { graceSeconds: 600 });

    expect(created.kid).not.toBe(old.kid);
    expect(await statuses(tenant.id)).toEqual(["active", "retiring"]);
    expect((await getActiveKey(tenant.id)).kid).toBe(created.kid);
    expect(await graceOf(old.kid)).toBeGreaterThanOrEqual(598);
  });

  it("defaults grace to the longest TTL in the tenant", async () => {
    const tenant = await createTenant({ defaultTokenTtlSeconds: 900 });
    await db
      .insert(resources)
      .values({ tenantId: tenant.id, name: "r", audience: "https://r", tokenTtlSeconds: 7200 });
    await db.insert(resources).values({ tenantId: tenant.id, name: "r2", audience: "https://r2" });
    await db
      .insert(applications)
      .values({ tenantId: tenant.id, name: "a", clientId: "app_aaaaaaaaaaaaaaaaaaaa" });

    const old = await ensureActiveKey(tenant.id);
    await rotateKey(tenant.id);
    const grace = await graceOf(old.kid);
    expect(grace).toBeGreaterThan(7190);
    expect(grace).toBeLessThanOrEqual(7200);
  });

  it("only touches the given tenant", async () => {
    const a = await createTenant();
    const b = await createTenant();
    await ensureActiveKey(a.id);
    const bKey = await ensureActiveKey(b.id);
    await rotateKey(a.id);
    expect(await statuses(b.id)).toEqual(["active"]);
    expect((await getActiveKey(b.id)).kid).toBe(bKey.kid);
  });
});

describe("getJwks", () => {
  it("serves active + retiring keys, active first, public members only", async () => {
    const tenant = await createTenant();
    const old = await ensureActiveKey(tenant.id);
    const created = await rotateKey(tenant.id, { graceSeconds: 600 });

    const jwks = await getJwks(tenant.id);
    expect(jwks.keys.map((k) => k.kid)).toEqual([created.kid, old.kid]);
    for (const key of jwks.keys) {
      expect(Object.keys(key).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x", "y"]);
      expect(key).toMatchObject({ kty: "EC", crv: "P-256", use: "sig", alg: "ES256" });
    }
    expect(JSON.stringify(jwks)).not.toContain('"d"');
  });

  it("drops the retiring key once retires_at passes and retireExpiredKeys runs", async () => {
    const tenant = await createTenant();
    const old = await ensureActiveKey(tenant.id);
    const created = await rotateKey(tenant.id, { graceSeconds: 600 });

    expect(await retireExpiredKeys()).toBe(0);
    await db
      .update(signingKeys)
      .set({ retiresAt: sql`now() - interval '1 second'` })
      .where(eq(signingKeys.kid, old.kid));

    expect(await retireExpiredKeys()).toBe(1);
    expect((await getJwks(tenant.id)).keys.map((k) => k.kid)).toEqual([created.kid]);
    expect(await statuses(tenant.id)).toEqual(["active", "retired"]);
  });

  it("a token signed with the now-retiring key still verifies (Review Focus 3)", async () => {
    const tenant = await createTenant();
    const before = await getActiveKey(tenant.id);
    const token = await signAccessToken(before.privateKeyPem, before.kid, claims());

    await rotateKey(tenant.id, { graceSeconds: 600 });
    const payload = await verifyAccessToken(token, await getJwks(tenant.id), { issuer: ISSUER });
    expect(payload.sub).toBe("app_x");

    await db
      .update(signingKeys)
      .set({ retiresAt: sql`now() - interval '1 second'` })
      .where(eq(signingKeys.kid, before.kid));
    await retireExpiredKeys();
    await expect(
      verifyAccessToken(token, await getJwks(tenant.id), { issuer: ISSUER }),
    ).rejects.toThrow();
  });

  it("does not leak another tenant's keys", async () => {
    const a = await createTenant();
    const b = await createTenant();
    const aKey = await ensureActiveKey(a.id);
    await ensureActiveKey(b.id);
    expect((await getJwks(a.id)).keys.map((k) => k.kid)).toEqual([aKey.kid]);
  });
});

describe("autoRotateDueKeys", () => {
  it("rotates only tenants with key_rotation_days whose active key is older", async () => {
    const due = await createTenant({ keyRotationDays: 30 });
    const fresh = await createTenant({ keyRotationDays: 30 });
    const manual = await createTenant();
    const dueKey = await ensureActiveKey(due.id);
    await ensureActiveKey(fresh.id);
    await ensureActiveKey(manual.id);
    await db
      .update(signingKeys)
      .set({ createdAt: sql`now() - interval '31 days'` })
      .where(inArray(signingKeys.tenantId, [due.id, manual.id]));

    expect(await autoRotateDueKeys()).toBe(1);
    expect(await statuses(due.id)).toEqual(["active", "retiring"]);
    expect((await getActiveKey(due.id)).kid).not.toBe(dueKey.kid);
    expect(await statuses(fresh.id)).toEqual(["active"]);
    expect(await statuses(manual.id)).toEqual(["active"]);

    expect(await autoRotateDueKeys()).toBe(0);
  });
});
