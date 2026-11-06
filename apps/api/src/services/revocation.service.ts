import { db, revokedTokens } from "@handsal/db";
import { lt, sql } from "drizzle-orm";
import { decodeJwt } from "jose";
import { createLogger } from "../utils/logger.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import { verifyTenantToken } from "./introspection.service.js";
import type { Tenant } from "./tenant.service.js";
import { recordTokenEvent } from "./token-event.service.js";

const logger = createLogger("revocation-service");

/**
 * RFC 7009 revocation by the client the token was issued to. Invalid tokens and tokens
 * of other clients are ignored silently (§2.2: the endpoint answers 200 either way).
 */
export async function revokeToken(
  tenant: Tenant,
  callerApplication: AuthenticatedApplication,
  token: string,
  ctx: { sourceIp: string },
): Promise<void> {
  // Unverified decode only to skip the signature check for obviously foreign tokens.
  let unverifiedClientId: unknown;
  try {
    unverifiedClientId = decodeJwt(token).client_id;
  } catch {
    return;
  }
  if (unverifiedClientId !== callerApplication.clientId) return;

  const claims = await verifyTenantToken(tenant, token);
  if (!claims || claims.client_id !== callerApplication.clientId) return;

  const expiresAt = new Date(claims.exp * 1000);
  await db
    .insert(revokedTokens)
    .values({ jti: claims.jti, tenantId: tenant.id, expiresAt })
    .onConflictDoNothing({ target: revokedTokens.jti });

  await recordTokenEvent({
    tenantId: tenant.id,
    applicationId: callerApplication.id,
    applicationClientId: callerApplication.clientId,
    audience: claims.aud.slice(0, 512),
    outcome: "revoked",
    scopes: claims.scope.split(" ").filter(Boolean),
    jti: claims.jti,
    expiresAt,
    sourceIp: ctx.sourceIp.slice(0, 45),
  });
}

/** Delete revocations whose token has expired anyway (all tenants). Returns the deleted count. */
export async function purgeExpiredRevocations(): Promise<number> {
  const result = await db.delete(revokedTokens).where(lt(revokedTokens.expiresAt, sql`now()`));
  const deleted = result.rowCount ?? 0;
  if (deleted > 0) logger.info({ deleted }, "Purged expired revoked tokens");
  return deleted;
}
