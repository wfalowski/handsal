import { applicationKeys, applications, db, type tenants } from "@handsal/db";
import {
  ASSERTION_CLOCK_TOLERANCE_SECONDS,
  ASSERTION_MAX_LIFETIME_SECONDS,
  OAUTH_ERRORS,
} from "@handsal/shared";
import { and, eq, gt, or, sql } from "drizzle-orm";
import { errors, importSPKI, type JWTPayload, jwtVerify } from "jose";
import { env } from "../env.js";
import { OAuthError } from "../middleware/error-handler.js";
import { assertionClientId } from "../utils/client-assertion.js";
import { hashSecret, verifySecret } from "../utils/crypto.js";
import { decodeHeader } from "../utils/jwt.js";
import { logSecurityEvent, SecurityEvent, SecuritySeverity } from "../utils/security-logger.js";
import { MemoryStore } from "../utils/store.js";

type Tenant = typeof tenants.$inferSelect;
type ApplicationRow = typeof applications.$inferSelect;
/** The authenticated application row, without secret hashes. */
export type AuthenticatedApplication = Omit<
  ApplicationRow,
  "clientSecretHash" | "previousSecretHash"
>;

export type ClientAuthFailureReason =
  | "unknown_client"
  | "auth_method_mismatch"
  | "bad_secret"
  | "client_disabled"
  | "bad_assertion"
  | "unknown_assertion_key"
  | "assertion_expired"
  | "assertion_not_yet_valid"
  | "assertion_replayed";

// Verified against for unknown/mismatched clients so every failure costs one argon2 verify.
// The private_key_jwt path is not timing-equalised; client ids are high-entropy and not secret.
const DUMMY_HASH_PROMISE = hashSecret("handsal-dummy-secret-for-timing-safety");

async function burnDummyVerify(secret: string, lane: string): Promise<void> {
  await verifySecret(secret, await DUMMY_HASH_PROMISE, lane);
}

function fail(
  tenantId: string,
  clientId: string,
  sourceIp: string,
  reason: ClientAuthFailureReason,
): never {
  logSecurityEvent({
    event: SecurityEvent.CLIENT_AUTH_FAILURE,
    severity: SecuritySeverity.HIGH,
    tenantId,
    clientId,
    sourceIp,
    details: { reason },
  });
  // Same public message for every reason; `reason` is for logs and token events only.
  const err = new OAuthError(OAUTH_ERRORS.INVALID_CLIENT, 401, "Invalid client credentials");
  err.securityLogged = true;
  err.reason = reason;
  throw err;
}

async function secretMatches(app: ApplicationRow, secret: string, lane: string): Promise<boolean> {
  if (!app.clientSecretHash) {
    await burnDummyVerify(secret, lane);
    return false;
  }
  if (await verifySecret(secret, app.clientSecretHash, lane)) return true;
  return (
    app.previousSecretHash !== null &&
    app.previousSecretExpiresAt !== null &&
    Date.now() < app.previousSecretExpiresAt.getTime() &&
    verifySecret(secret, app.previousSecretHash, lane)
  );
}

/**
 * Authenticates a client of `tenant` (client_secret_basic / client_secret_post).
 * Throws `OAuthError(invalid_client, 401)` with `err.reason` set on any failure.
 */
export async function authenticateClient(
  tenant: Tenant,
  credentials: { clientId: string; clientSecret: string; viaBasic: boolean },
  sourceIp: string,
): Promise<{ application: AuthenticatedApplication }> {
  const { clientId, clientSecret, viaBasic } = credentials;

  const [app] = await db
    .select()
    .from(applications)
    .where(and(eq(applications.tenantId, tenant.id), eq(applications.clientId, clientId)))
    .limit(1);

  if (!app) {
    await burnDummyVerify(clientSecret, sourceIp);
    fail(tenant.id, clientId, sourceIp, "unknown_client");
  }

  const expectedMethod = viaBasic ? "client_secret_basic" : "client_secret_post";
  if (app.tokenEndpointAuthMethod !== expectedMethod) {
    await burnDummyVerify(clientSecret, sourceIp);
    fail(tenant.id, clientId, sourceIp, "auth_method_mismatch");
  }

  if (!(await secretMatches(app, clientSecret, sourceIp))) {
    fail(tenant.id, clientId, sourceIp, "bad_secret");
  }

  // Checked only after the secret verified, so status is not an oracle for unauthenticated callers.
  if (app.status === "disabled") {
    fail(tenant.id, clientId, sourceIp, "client_disabled");
  }

  const { clientSecretHash: _c, previousSecretHash: _p, ...application } = app;
  return { application };
}

export { assertionClientId };

/** Cap on live replay entries; beyond it the oldest jti is evicted (bounds memory). */
const ASSERTION_JTI_MAX_KEYS = 100_000;
const MAX_JTI_LENGTH = 128;

// shortcut: process-local replay cache, so an assertion can be replayed once per replica; move to a shared store with the rate limiter.
const assertionJtis = new MemoryStore<true>(60_000, ASSERTION_JTI_MAX_KEYS);

function timeClaimReason(err: unknown): ClientAuthFailureReason | undefined {
  if (err instanceof errors.JWTExpired) return "assertion_expired";
  if (err instanceof errors.JWTClaimValidationFailed && err.claim === "nbf") {
    return "assertion_not_yet_valid";
  }
  return undefined;
}

/**
 * Authenticates a client of `tenant` by an RFC 7523 `private_key_jwt` assertion.
 * `claimedClientId` is the request's `client_id`, which must match the assertion when sent.
 * Throws `OAuthError(invalid_client, 401)` with `err.reason` set on any failure.
 */
export async function authenticateClientAssertion(
  tenant: Tenant,
  assertion: string,
  sourceIp: string,
  claimedClientId?: string,
): Promise<{ application: AuthenticatedApplication }> {
  // Everything before jwtVerify reads unverified input: every failure is the same opaque 401.
  const { alg, kid } = decodeHeader(assertion);
  const clientId = assertionClientId(assertion);
  if (alg !== "ES256" || !kid || !clientId) {
    fail(tenant.id, clientId ?? claimedClientId ?? "", sourceIp, "bad_assertion");
  }
  if (claimedClientId !== undefined && claimedClientId !== clientId) {
    fail(tenant.id, claimedClientId, sourceIp, "bad_assertion");
  }

  const [app] = await db
    .select()
    .from(applications)
    .where(and(eq(applications.tenantId, tenant.id), eq(applications.clientId, clientId)))
    .limit(1);
  if (!app) fail(tenant.id, clientId, sourceIp, "unknown_client");
  if (app.tokenEndpointAuthMethod !== "private_key_jwt") {
    fail(tenant.id, clientId, sourceIp, "auth_method_mismatch");
  }

  const [key] = await db
    .select({ publicKeyPem: applicationKeys.publicKeyPem })
    .from(applicationKeys)
    .where(
      and(
        eq(applicationKeys.tenantId, tenant.id),
        eq(applicationKeys.applicationId, app.id),
        eq(applicationKeys.kid, kid),
        or(
          eq(applicationKeys.status, "active"),
          and(eq(applicationKeys.status, "retiring"), gt(applicationKeys.retiresAt, sql`now()`)),
        ),
      ),
    )
    .limit(1);
  if (!key) fail(tenant.id, clientId, sourceIp, "unknown_assertion_key");

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(assertion, await importSPKI(key.publicKeyPem, "ES256"), {
      algorithms: ["ES256"],
      issuer: clientId,
      subject: clientId,
      audience: `${env.PUBLIC_URL}/t/${tenant.slug}/oauth/token`,
      clockTolerance: ASSERTION_CLOCK_TOLERANCE_SECONDS,
    }));
  } catch (err) {
    fail(tenant.id, clientId, sourceIp, timeClaimReason(err) ?? "bad_assertion");
  }

  const now = Math.floor(Date.now() / 1000);
  const { exp, iat, jti } = payload;
  if (
    typeof jti !== "string" ||
    jti.length === 0 ||
    jti.length > MAX_JTI_LENGTH ||
    exp === undefined ||
    // Tolerance applies here too, or a client with a slightly fast clock and a 300 s lifetime is locked out.
    exp - now > ASSERTION_MAX_LIFETIME_SECONDS + ASSERTION_CLOCK_TOLERANCE_SECONDS ||
    (iat !== undefined && iat > now + ASSERTION_CLOCK_TOLERANCE_SECONDS)
  ) {
    fail(tenant.id, clientId, sourceIp, "bad_assertion");
  }

  // Recorded only after the signature verified, so an unsigned forgery cannot burn a real jti.
  const replayKey = `${tenant.id}:${clientId}:${jti}`;
  if (await assertionJtis.has(replayKey)) {
    fail(tenant.id, clientId, sourceIp, "assertion_replayed");
  }
  const ttlMs = exp * 1000 - Date.now() + ASSERTION_CLOCK_TOLERANCE_SECONDS * 1000;
  const maxTtlMs = (ASSERTION_MAX_LIFETIME_SECONDS + 2 * ASSERTION_CLOCK_TOLERANCE_SECONDS) * 1000;
  await assertionJtis.set(replayKey, true, Math.min(Math.max(ttlMs, 1), maxTtlMs));

  // Checked last, so status is not an oracle for unauthenticated callers.
  if (app.status === "disabled") {
    fail(tenant.id, clientId, sourceIp, "client_disabled");
  }

  const { clientSecretHash: _c, previousSecretHash: _p, ...application } = app;
  return { application };
}
