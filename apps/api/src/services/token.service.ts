import { randomUUID } from "node:crypto";
import { applications, db, scopes } from "@handsal/db";
import { OAUTH_ERRORS, TOKEN_TYPES } from "@handsal/shared";
import { and, eq, inArray, sql } from "drizzle-orm";
import { env } from "../env.js";
import { OAuthError } from "../middleware/error-handler.js";
import { signAccessToken } from "../utils/jwt.js";
import { createLogger } from "../utils/logger.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import { getGrantedScopesForAudience } from "./grant.service.js";
import { getActiveKey } from "./signing-key.service.js";
import type { Tenant } from "./tenant.service.js";
import { recordTokenEvent } from "./token-event.service.js";

const logger = createLogger("token-service");

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

function deny(code: string, description: string, reason: string): never {
  const err = new OAuthError(code, 400, description);
  err.reason = reason;
  throw err;
}

/** Issue a client-credentials access token for an already authenticated application. */
export async function issueToken(
  tenant: Tenant,
  application: AuthenticatedApplication,
  request: { audience: string; requestedScopes?: string[] },
  ctx: { sourceIp: string },
): Promise<TokenResponse> {
  if (tenant.status === "paused") {
    deny(OAUTH_ERRORS.INVALID_REQUEST, "tenant paused", "tenant_paused");
  }

  // Same answer for unknown, foreign-tenant, ungranted and disabled resources: no existence oracle.
  const granted = await getGrantedScopesForAudience(tenant.id, application.id, request.audience);
  if (granted?.resource.status !== "active") {
    deny(OAUTH_ERRORS.INVALID_TARGET, "Unknown or unauthorized resource", "invalid_target");
  }
  const { resource, scopeNames } = granted;

  const requested = request.requestedScopes?.length ? [...new Set(request.requestedScopes)] : null;
  if (requested?.some((s) => !scopeNames.includes(s))) {
    deny(OAUTH_ERRORS.INVALID_SCOPE, "Requested scope is not granted", "invalid_scope");
  }
  const tokenScopes = requested ?? scopeNames;

  if (application.kind === "agent") {
    const [forbidden] = await db
      .select({ name: scopes.name })
      .from(scopes)
      .where(
        and(
          eq(scopes.tenantId, tenant.id),
          eq(scopes.resourceId, resource.id),
          inArray(scopes.name, tokenScopes),
          eq(scopes.agentPolicy, "never"),
        ),
      )
      .limit(1);
    if (forbidden) {
      deny(
        OAUTH_ERRORS.INVALID_SCOPE,
        "Requested scope is not available to agents",
        "invalid_scope",
      );
    }
  }

  const ttl =
    application.tokenTtlSeconds ?? resource.tokenTtlSeconds ?? tenant.defaultTokenTtlSeconds;
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttl;
  const jti = randomUUID();
  const scope = tokenScopes.join(" ");

  const { kid, privateKeyPem } = await getActiveKey(tenant.id);
  const accessToken = await signAccessToken(privateKeyPem, kid, {
    iss: `${env.PUBLIC_URL}/t/${tenant.slug}`,
    sub: application.clientId,
    client_id: application.clientId,
    aud: request.audience,
    scope,
    tenant: tenant.slug,
    client_kind: application.kind,
    jti,
    iat,
    exp,
  });

  await recordTokenEvent({
    tenantId: tenant.id,
    applicationId: application.id,
    applicationClientId: application.clientId,
    resourceId: resource.id,
    audience: request.audience,
    outcome: "issued",
    scopes: tokenScopes,
    jti,
    expiresAt: new Date(exp * 1000),
    sourceIp: ctx.sourceIp.slice(0, 45),
  });
  try {
    await db
      .update(applications)
      // Keep updated_at: a token request is not an edit of the application.
      .set({ lastTokenAt: new Date(), updatedAt: sql`${applications.updatedAt}` })
      .where(and(eq(applications.tenantId, tenant.id), eq(applications.id, application.id)));
  } catch (err) {
    logger.error(
      { err, tenantId: tenant.id, applicationId: application.id },
      "Failed to update last_token_at",
    );
  }

  return { access_token: accessToken, token_type: TOKEN_TYPES.BEARER, expires_in: ttl, scope };
}
