import { randomUUID } from "node:crypto";
import { applications, db, scopes, tokenEvents } from "@handsal/db";
import { OAUTH_ERRORS, TOKEN_TYPES } from "@handsal/shared";
import { and, eq, gte, inArray, sql } from "drizzle-orm";
import { env } from "../env.js";
import { OAuthError } from "../middleware/error-handler.js";
import { ipInCidrs } from "../utils/cidr.js";
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

/**
 * Tokens issued to this application in the trailing hour, plus the seconds until the oldest of
 * them leaves the window (1-3600; 1 when none).
 */
export async function countIssuedLastHour(
  tenantId: string,
  applicationId: string,
): Promise<{ count: number; retryAfterSeconds: number }> {
  const [row] = await db
    .select({
      count: sql<number>`count(*)::int`,
      untilOldestExpires: sql<
        number | null
      >`ceil(extract(epoch from min(${tokenEvents.createdAt}) + interval '1 hour' - now()))::int`,
    })
    .from(tokenEvents)
    .where(
      and(
        eq(tokenEvents.tenantId, tenantId),
        eq(tokenEvents.applicationId, applicationId),
        eq(tokenEvents.outcome, "issued"),
        gte(tokenEvents.createdAt, sql`now() - interval '1 hour'`),
      ),
    );
  const retryAfterSeconds = Math.min(3600, Math.max(1, row.untilOldestExpires ?? 1));
  return { count: row.count, retryAfterSeconds };
}

/** Agent guardrails (6.2): source CIDR, scope ceiling, hourly budget. No-op for services. */
async function enforceAgentGuardrails(
  tenant: Tenant,
  application: AuthenticatedApplication,
  tokenScopes: string[],
  sourceIp: string,
): Promise<void> {
  if (application.kind !== "agent") return;

  let ipAllowed = false;
  try {
    ipAllowed = ipInCidrs(sourceIp, application.allowedCidrs);
  } catch (err) {
    // A corrupt stored CIDR fails closed.
    logger.error({ err, tenantId: tenant.id, applicationId: application.id }, "Bad allowed_cidrs");
  }
  if (!ipAllowed) {
    deny(OAUTH_ERRORS.UNAUTHORIZED_CLIENT, "Source address is not allowed", "cidr_denied");
  }

  // shortcut: with `scope` omitted the whole grant counts, so an over-granted agent must request explicitly (intended least-privilege nudge).
  if (
    application.maxScopesPerToken !== null &&
    tokenScopes.length > application.maxScopesPerToken
  ) {
    deny(OAUTH_ERRORS.INVALID_SCOPE, "Too many scopes requested for one token", "scope_ceiling");
  }

  if (application.tokenBudgetPerHour !== null) {
    // shortcut: read is not serialised with the insert, so concurrent requests can overshoot by the in-flight count; a counter row would make it exact.
    const { count, retryAfterSeconds } = await countIssuedLastHour(tenant.id, application.id);
    if (count >= application.tokenBudgetPerHour) {
      const err = new OAuthError("too_many_requests", 429, "Hourly token budget exhausted");
      err.reason = "budget_exhausted";
      err.retryAfterSeconds = retryAfterSeconds;
      throw err;
    }
  }
}

/** Issue a client-credentials access token for an already authenticated application. */
export async function issueToken(
  tenant: Tenant,
  application: AuthenticatedApplication,
  request: { audience: string; requestedScopes?: string[]; taskId?: string },
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

  await enforceAgentGuardrails(tenant, application, tokenScopes, ctx.sourceIp);

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
    ...(request.taskId && { task_id: request.taskId }),
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
    taskId: request.taskId ?? null,
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
