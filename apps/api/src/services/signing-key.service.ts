import { db, signingKeys, tenants } from "@handsal/db";
import { DEFAULTS } from "@handsal/shared";
import { and, asc, desc, eq, gt, inArray, lte, or, sql } from "drizzle-orm";
import { exportJWK, importSPKI, type JSONWebKeySet, type JWK } from "jose";
import { env } from "../env.js";
import { decryptPrivateKey, encryptPrivateKey } from "../utils/crypto.js";
import { generateEs256KeyPair, makeKid } from "../utils/key-management.js";
import { createLogger } from "../utils/logger.js";

const logger = createLogger("signing-key-service");

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];

/** A signing key row without its (encrypted) private key. */
export type SigningKey = Omit<typeof signingKeys.$inferSelect, "privateKeyEnc">;

/** What the token service needs to sign: the active kid and its decrypted private key. */
export interface ActiveSigningKey {
  kid: string;
  privateKeyPem: string;
}

const publicColumns = {
  id: signingKeys.id,
  tenantId: signingKeys.tenantId,
  kid: signingKeys.kid,
  algorithm: signingKeys.algorithm,
  publicKeyPem: signingKeys.publicKeyPem,
  status: signingKeys.status,
  retiresAt: signingKeys.retiresAt,
  createdAt: signingKeys.createdAt,
  updatedAt: signingKeys.updatedAt,
};

// kid has only 16 random bits per day, so collisions across tenants are
// plausible; regenerate on conflict.
const MAX_KID_ATTEMPTS = 5;

/**
 * Insert a new active key. Returns null when another active key already exists
 * (partial unique index), so callers can decide how to react.
 */
async function insertActiveKey(tx: Tx | typeof db, tenantId: string): Promise<SigningKey | null> {
  const { publicKeyPem, privateKeyPem } = generateEs256KeyPair();
  const privateKeyEnc = encryptPrivateKey(privateKeyPem, env.KEY_ENCRYPTION_SECRET);
  for (let attempt = 0; attempt < MAX_KID_ATTEMPTS; attempt++) {
    const kid = makeKid();
    const [row] = await tx
      .insert(signingKeys)
      .values({ tenantId, kid, publicKeyPem, privateKeyEnc, status: "active" })
      .onConflictDoNothing()
      .returning(publicColumns);
    if (row) return row;
    const [kidTaken] = await tx
      .select({ id: signingKeys.id })
      .from(signingKeys)
      .where(eq(signingKeys.kid, kid));
    if (!kidTaken) return null; // conflict was the one-active-per-tenant index
  }
  throw new Error("Could not generate a unique signing key id");
}

async function selectActiveKey(
  tx: Tx | typeof db,
  tenantId: string,
): Promise<SigningKey | undefined> {
  const [row] = await tx
    .select(publicColumns)
    .from(signingKeys)
    .where(and(eq(signingKeys.tenantId, tenantId), eq(signingKeys.status, "active")));
  return row;
}

/**
 * Return the tenant's active key, creating one when there is none (idempotent, race-safe).
 * Pass `tx` to run inside a caller's transaction (e.g. right after inserting the tenant).
 */
export async function ensureActiveKey(
  tenantId: string,
  tx: Tx | typeof db = db,
): Promise<SigningKey> {
  for (let attempt = 0; attempt < MAX_KID_ATTEMPTS; attempt++) {
    const existing = await selectActiveKey(tx, tenantId);
    if (existing) return existing;
    const created = await insertActiveKey(tx, tenantId);
    if (created) {
      logger.info({ tenantId, kid: created.kid }, "Created signing key");
      return created;
    }
    // Lost a race with a concurrent creator; loop re-reads the winner.
  }
  throw new Error("Could not ensure an active signing key");
}

/** The key new tokens are signed with (created on first use). Never a retiring key. */
export async function getActiveKey(tenantId: string): Promise<ActiveSigningKey> {
  // kid + private key in one statement: a rotation between two reads could hand back a retiring key.
  const selectActive = () =>
    db
      .select({ kid: signingKeys.kid, privateKeyEnc: signingKeys.privateKeyEnc })
      .from(signingKeys)
      .where(and(eq(signingKeys.tenantId, tenantId), eq(signingKeys.status, "active")));
  let [row] = await selectActive();
  if (!row) {
    await ensureActiveKey(tenantId);
    [row] = await selectActive();
  }
  if (!row) throw new Error("Active signing key disappeared");
  return {
    kid: row.kid,
    privateKeyPem: decryptPrivateKey(row.privateKeyEnc, env.KEY_ENCRYPTION_SECRET),
  };
}

/** All keys of the tenant (any status), newest first. Public material only. */
export async function listKeys(tenantId: string): Promise<SigningKey[]> {
  return db
    .select(publicColumns)
    .from(signingKeys)
    .where(eq(signingKeys.tenantId, tenantId))
    .orderBy(desc(signingKeys.createdAt));
}

/**
 * Longest token TTL configurable in the tenant (tenant default, resources,
 * applications; nulls ignored), at least TTL_MIN. A retiring key must stay in
 * the JWKS at least this long so every token it signed can still be verified.
 */
async function maxTokenTtlSeconds(tx: Tx, tenantId: string): Promise<number> {
  const result = await tx.execute<{ max_ttl: number | null }>(sql`
    select greatest(
      t.default_token_ttl_seconds,
      (select max(r.token_ttl_seconds) from resources r where r.tenant_id = t.id),
      (select max(a.token_ttl_seconds) from applications a where a.tenant_id = t.id)
    ) as max_ttl
    from tenants t
    where t.id = ${tenantId}
  `);
  return Math.max(Number(result.rows[0]?.max_ttl ?? 0), DEFAULTS.TTL_MIN);
}

/**
 * Rotate the tenant's signing key: the current active key becomes `retiring`
 * (still published in JWKS until `retires_at = now + grace`) and a new active
 * key is created. Returns the new active key.
 */
export async function rotateKey(
  tenantId: string,
  options: { graceSeconds?: number } = {},
): Promise<SigningKey> {
  const created = await db.transaction(async (tx) => {
    // Serialize concurrent rotations of the same tenant.
    const [tenant] = await tx
      .select({ id: tenants.id })
      .from(tenants)
      .where(eq(tenants.id, tenantId))
      .for("update");
    if (!tenant) throw new Error(`Tenant ${tenantId} not found`);

    const graceSeconds = options.graceSeconds ?? (await maxTokenTtlSeconds(tx, tenantId));

    // Retire first: the partial unique index allows only one active key.
    await tx
      .update(signingKeys)
      .set({
        status: "retiring",
        retiresAt: sql`now() + make_interval(secs => ${graceSeconds})`,
      })
      .where(and(eq(signingKeys.tenantId, tenantId), eq(signingKeys.status, "active")));

    const key = await insertActiveKey(tx, tenantId);
    if (!key) throw new Error("Active signing key still present after retiring it");
    return key;
  });
  logger.info({ tenantId, kid: created.kid }, "Rotated signing key");
  return created;
}

/** Flip `retiring` keys whose `retires_at` has passed to `retired`. Returns the count. */
export async function retireExpiredKeys(): Promise<number> {
  const rows = await db
    .update(signingKeys)
    .set({ status: "retired" })
    .where(and(eq(signingKeys.status, "retiring"), lte(signingKeys.retiresAt, sql`now()`)))
    .returning({ kid: signingKeys.kid });
  if (rows.length > 0) {
    logger.info({ kids: rows.map((r) => r.kid) }, "Retired signing keys");
  }
  return rows.length;
}

/**
 * Rotate every tenant with `key_rotation_days` set whose active key is older
 * than that. A failure for one tenant is logged and does not stop the others.
 * Returns the number of tenants rotated.
 */
export async function autoRotateDueKeys(): Promise<number> {
  const due = await db
    .select({ tenantId: tenants.id })
    .from(tenants)
    .innerJoin(
      signingKeys,
      and(eq(signingKeys.tenantId, tenants.id), eq(signingKeys.status, "active")),
    )
    .where(
      sql`${tenants.keyRotationDays} is not null and ${signingKeys.createdAt} < now() - make_interval(days => ${tenants.keyRotationDays})`,
    );

  let rotated = 0;
  for (const { tenantId } of due) {
    try {
      await rotateKey(tenantId);
      rotated++;
    } catch (err) {
      logger.error({ err, tenantId }, "Automatic signing key rotation failed");
    }
  }
  return rotated;
}

/** Public JWKS: active + retiring (until `retires_at`) keys, active first. Never private members. */
export async function getJwks(tenantId: string): Promise<JSONWebKeySet> {
  const rows = await db
    .select({ kid: signingKeys.kid, publicKeyPem: signingKeys.publicKeyPem })
    .from(signingKeys)
    .where(
      and(
        eq(signingKeys.tenantId, tenantId),
        inArray(signingKeys.status, ["active", "retiring"]),
        or(eq(signingKeys.status, "active"), gt(signingKeys.retiresAt, sql`now()`)),
      ),
    )
    // pg enum order is active < retiring < retired
    .orderBy(asc(signingKeys.status), desc(signingKeys.createdAt));

  const keys = await Promise.all(
    rows.map(async (row): Promise<JWK> => {
      const { kty, crv, x, y } = await exportJWK(await importSPKI(row.publicKeyPem, "ES256"));
      return { kty, crv, x, y, kid: row.kid, use: "sig", alg: "ES256" };
    }),
  );
  return { keys };
}
