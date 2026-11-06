import { applications, db, revokedTokens } from "@handsal/db";
import { and, eq } from "drizzle-orm";
import type { JWTPayload } from "jose";
import { env } from "../env.js";
import { verifyAccessToken } from "../utils/jwt.js";
import { getJwks } from "./signing-key.service.js";
import type { Tenant } from "./tenant.service.js";

export type IntrospectionResponse =
  | { active: false }
  | {
      active: true;
      scope: string;
      client_id: string;
      token_type: "Bearer";
      exp: number;
      iat: number;
      sub: string;
      aud: string;
      iss: string;
      jti: string;
      tenant: string;
      client_kind: string;
    };

/** Claims every Handsal access token carries (see `issueToken`). */
export interface AccessTokenClaims {
  iss: string;
  sub: string;
  client_id: string;
  aud: string;
  scope: string;
  tenant: string;
  client_kind: string;
  jti: string;
  iat: number;
  exp: number;
}

function hasClaims(p: JWTPayload): p is JWTPayload & AccessTokenClaims {
  return (
    typeof p.sub === "string" &&
    typeof p.client_id === "string" &&
    typeof p.aud === "string" &&
    typeof p.scope === "string" &&
    typeof p.tenant === "string" &&
    typeof p.client_kind === "string" &&
    typeof p.jti === "string" &&
    typeof p.iat === "number" &&
    typeof p.exp === "number"
  );
}

/**
 * Verify `token` against the tenant's JWKS (active + retiring keys) and issuer.
 * Returns the claims, or null for anything invalid/expired/foreign. Never throws on bad input.
 */
export async function verifyTenantToken(
  tenant: Tenant,
  token: string,
): Promise<AccessTokenClaims | null> {
  try {
    const payload = await verifyAccessToken(token, await getJwks(tenant.id), {
      issuer: `${env.PUBLIC_URL}/t/${tenant.slug}`,
    });
    return hasClaims(payload) ? payload : null;
  } catch {
    return null;
  }
}

/**
 * "Not before" rule: a token is inactive when it was issued before a "revoke all" mark,
 * i.e. `iat * 1000 < tokensNotBefore`. `iat` has second precision, so a token issued in the
 * same second right after the mark is also treated as revoked (errs on the safe side).
 */
function issuedBefore(iatSeconds: number, notBefore: Date | null): boolean {
  return notBefore !== null && iatSeconds * 1000 < notBefore.getTime();
}

/** RFC 7662 introspection for a token of `tenant`. `{ active: false }` on any problem. */
export async function introspectToken(
  tenant: Tenant,
  token: string,
): Promise<IntrospectionResponse> {
  const inactive = { active: false } as const;
  if (tenant.status !== "active") return inactive;

  const claims = await verifyTenantToken(tenant, token);
  if (!claims || issuedBefore(claims.iat, tenant.tokensNotBefore)) return inactive;

  const [[app], [revoked]] = await Promise.all([
    db
      .select({ status: applications.status, tokensNotBefore: applications.tokensNotBefore })
      .from(applications)
      .where(and(eq(applications.tenantId, tenant.id), eq(applications.clientId, claims.client_id)))
      .limit(1),
    db
      .select({ jti: revokedTokens.jti })
      .from(revokedTokens)
      .where(and(eq(revokedTokens.tenantId, tenant.id), eq(revokedTokens.jti, claims.jti)))
      .limit(1),
  ]);
  // Missing (deleted) or disabled application, or revoked jti.
  if (app?.status !== "active" || revoked) return inactive;
  if (issuedBefore(claims.iat, app.tokensNotBefore)) return inactive;

  return {
    active: true,
    scope: claims.scope,
    client_id: claims.client_id,
    token_type: "Bearer",
    exp: claims.exp,
    iat: claims.iat,
    sub: claims.sub,
    aud: claims.aud,
    iss: claims.iss,
    jti: claims.jti,
    tenant: claims.tenant,
    client_kind: claims.client_kind,
  };
}
