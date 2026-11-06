import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { applicationKeys, applications, db } from "@handsal/db";
import type {
  ApplicationKeyDto,
  applicationKeyCreateSchema,
  applicationKeyRetireSchema,
} from "@handsal/shared";
import { and, asc, eq, gt, or, type SQL, sql } from "drizzle-orm";
import type { z } from "zod";
import { ApiError } from "../middleware/error-handler.js";
import { getApplication } from "./application.service.js";

type ApplicationKeyRow = typeof applicationKeys.$inferSelect;
export type ApplicationKeyCreateInput = z.infer<typeof applicationKeyCreateSchema>;
export type ApplicationKeyRetireInput = z.infer<typeof applicationKeyRetireSchema>;

export function toApplicationKeyDto(row: ApplicationKeyRow): ApplicationKeyDto {
  return {
    id: row.id,
    applicationId: row.applicationId,
    kid: row.kid,
    algorithm: row.algorithm,
    fingerprintSha256: row.fingerprintSha256,
    status: row.status,
    retiresAt: row.retiresAt ? row.retiresAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const notFound = () => new ApiError(404, "application_key_not_found", "Application key not found");
const invalidKey = () =>
  new ApiError(
    400,
    "invalid_public_key",
    "Public key must be a P-256 public key in SPKI PEM format",
  );

/** Normalised SPKI PEM + lowercase hex SHA-256 over the DER SPKI; 400 for anything but a P-256 public key. */
function parseP256PublicKey(pem: string): { publicKeyPem: string; fingerprintSha256: string } {
  // createPublicKey also derives public keys from private keys and certificates; accept SPKI only.
  if (!pem.trim().startsWith("-----BEGIN PUBLIC KEY-----")) throw invalidKey();
  let key: KeyObject;
  try {
    key = createPublicKey({ key: pem, format: "pem" });
  } catch {
    throw invalidKey();
  }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw invalidKey();
  }
  const der = key.export({ type: "spki", format: "der" });
  return {
    publicKeyPem: key.export({ type: "spki", format: "pem" }).toString(),
    fingerprintSha256: createHash("sha256").update(der).digest("hex"),
  };
}

const lastKey = () =>
  new ApiError(
    409,
    "no_application_key",
    "Register another active public key before removing the last one of a private_key_jwt application",
  );

const KEY_CONSTRAINTS = new Set([
  "uq_application_keys_application_id_kid",
  "uq_application_keys_application_id_fingerprint",
]);

/** Maps the duplicate kid / fingerprint unique violations to 409; rethrows anything else. */
function mapConflict(err: unknown): never {
  const cause = (err as { cause?: { code?: string; constraint?: string } }).cause;
  if (cause?.code === "23505" && KEY_CONSTRAINTS.has(cause.constraint ?? "")) {
    throw new ApiError(
      409,
      "application_key_exists",
      "A key with this kid or public key is already registered",
    );
  }
  throw err;
}

export async function listApplicationKeys(
  tenantId: string,
  appId: string,
): Promise<ApplicationKeyDto[]> {
  await getApplication(tenantId, appId); // 404 for an unknown app / an app of another tenant
  const rows = await db
    .select()
    .from(applicationKeys)
    .where(and(eq(applicationKeys.tenantId, tenantId), eq(applicationKeys.applicationId, appId)))
    .orderBy(asc(applicationKeys.createdAt), asc(applicationKeys.kid));
  return rows.map(toApplicationKeyDto);
}

export async function createApplicationKey(
  tenantId: string,
  appId: string,
  input: ApplicationKeyCreateInput,
): Promise<ApplicationKeyDto> {
  await getApplication(tenantId, appId);
  const [row] = await db
    .insert(applicationKeys)
    .values({
      tenantId,
      applicationId: appId,
      kid: input.kid,
      ...parseP256PublicKey(input.publicKeyPem),
    })
    .returning()
    .catch(mapConflict);
  return toApplicationKeyDto(row);
}

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];

const activeKey = eq(applicationKeys.status, "active");
/** Keys client-auth still accepts: active, or retiring before `retires_at`. */
const usableKey = or(
  activeKey,
  and(eq(applicationKeys.status, "retiring"), gt(applicationKeys.retiresAt, sql`now()`)),
);

/**
 * Locks the application row (serialising concurrent key changes), then throws
 * `409 no_application_key` when a private_key_jwt application has no key matching `remaining`.
 */
async function assertKeyRemains(
  tx: Tx,
  tenantId: string,
  appId: string,
  remaining: SQL | undefined,
): Promise<void> {
  const [app] = await tx
    .select({ method: applications.tokenEndpointAuthMethod })
    .from(applications)
    .where(and(eq(applications.tenantId, tenantId), eq(applications.id, appId)))
    .for("update");
  if (app?.method !== "private_key_jwt") return;
  const [key] = await tx
    .select({ id: applicationKeys.id })
    .from(applicationKeys)
    .where(
      and(
        eq(applicationKeys.tenantId, tenantId),
        eq(applicationKeys.applicationId, appId),
        remaining,
      ),
    )
    .limit(1);
  if (!key) throw lastKey();
}

const keyWhere = (tenantId: string, appId: string, keyId: string) =>
  and(
    eq(applicationKeys.tenantId, tenantId),
    eq(applicationKeys.applicationId, appId),
    eq(applicationKeys.id, keyId),
  );

/**
 * Marks a key retiring; it keeps verifying assertions until `now + graceSeconds`.
 * 409 when it would leave a private_key_jwt application without an active key.
 */
export async function retireApplicationKey(
  tenantId: string,
  appId: string,
  keyId: string,
  input: ApplicationKeyRetireInput,
): Promise<ApplicationKeyDto> {
  return db.transaction(async (tx) => {
    const [row] = await tx
      .update(applicationKeys)
      .set({ status: "retiring", retiresAt: new Date(Date.now() + input.graceSeconds * 1000) })
      .where(keyWhere(tenantId, appId, keyId))
      .returning();
    if (!row) throw notFound();
    await assertKeyRemains(tx, tenantId, appId, activeKey); // throwing rolls the update back
    return toApplicationKeyDto(row);
  });
}

/** 409 when the key is the last usable one of a private_key_jwt application. */
export async function deleteApplicationKey(
  tenantId: string,
  appId: string,
  keyId: string,
): Promise<void> {
  await db.transaction(async (tx) => {
    const [row] = await tx
      .delete(applicationKeys)
      .where(keyWhere(tenantId, appId, keyId))
      .returning({ status: applicationKeys.status, retiresAt: applicationKeys.retiresAt });
    if (!row) throw notFound();
    const wasUsable =
      row.status === "active" ||
      (row.status === "retiring" && row.retiresAt !== null && row.retiresAt > new Date());
    // Deleting an already-unusable key changes nothing for client auth, so it is always allowed.
    if (wasUsable) await assertKeyRemains(tx, tenantId, appId, usableKey);
  });
}
