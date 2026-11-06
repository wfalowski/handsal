import { applications, db, type tenants } from "@handsal/db";
import { OAUTH_ERRORS } from "@handsal/shared";
import { and, eq } from "drizzle-orm";
import { OAuthError } from "../middleware/error-handler.js";
import { hashSecret, verifySecret } from "../utils/crypto.js";
import { logSecurityEvent, SecurityEvent, SecuritySeverity } from "../utils/security-logger.js";

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
  | "client_disabled";

// Verified against for unknown/mismatched clients so every failure costs one argon2 verify.
const DUMMY_HASH_PROMISE = hashSecret("handsal-dummy-secret-for-timing-safety");

async function burnDummyVerify(secret: string): Promise<void> {
  await verifySecret(secret, await DUMMY_HASH_PROMISE);
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

async function secretMatches(app: ApplicationRow, secret: string): Promise<boolean> {
  if (!app.clientSecretHash) {
    await burnDummyVerify(secret);
    return false;
  }
  if (await verifySecret(secret, app.clientSecretHash)) return true;
  return (
    app.previousSecretHash !== null &&
    app.previousSecretExpiresAt !== null &&
    Date.now() < app.previousSecretExpiresAt.getTime() &&
    verifySecret(secret, app.previousSecretHash)
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
    await burnDummyVerify(clientSecret);
    fail(tenant.id, clientId, sourceIp, "unknown_client");
  }

  const expectedMethod = viaBasic ? "client_secret_basic" : "client_secret_post";
  if (app.tokenEndpointAuthMethod !== expectedMethod) {
    await burnDummyVerify(clientSecret);
    fail(tenant.id, clientId, sourceIp, "auth_method_mismatch");
  }

  if (!(await secretMatches(app, clientSecret))) {
    fail(tenant.id, clientId, sourceIp, "bad_secret");
  }

  // Checked only after the secret verified, so status is not an oracle for unauthenticated callers.
  if (app.status === "disabled") {
    fail(tenant.id, clientId, sourceIp, "client_disabled");
  }

  const { clientSecretHash: _c, previousSecretHash: _p, ...application } = app;
  return { application };
}
