import { randomUUID } from "node:crypto";
import { applications, db, scopes } from "@handsal/db";
import { DEFAULTS, OAUTH_ERRORS, TOKEN_TYPES } from "@handsal/shared";
import { and, eq, inArray, sql } from "drizzle-orm";
import { env } from "../env.js";
import { OAuthError } from "../middleware/error-handler.js";
import { ipInCidrs } from "../utils/cidr.js";
import { signAccessToken } from "../utils/jwt.js";
import { createLogger } from "../utils/logger.js";
import { claimApproval, createApprovalRequest } from "./approval.service.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import { getGrantedScopesForAudience } from "./grant.service.js";
import { getActiveKey } from "./signing-key.service.js";
import type { Tenant } from "./tenant.service.js";
import { countIssuedLastHour, recordTokenEvent } from "./token-event.service.js";

const logger = createLogger("token-service");

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

/** The request needs a human: the agent polls the token endpoint with this id. */
export interface PendingApproval {
  approvalId: string;
  /** `approved` when an auto-approve rule decided at once: the agent may poll immediately. */
  status: "pending" | "approved";
}

export function deny(code: string, description: string, reason: string): never {
  const err = new OAuthError(code, 400, description);
  err.reason = reason;
  throw err;
}

/** Agent guardrails (6.2): source CIDR, scope ceiling, hourly budget. No-op for services. */
export async function enforceAgentGuardrails(
  tenant: Tenant,
  application: AuthenticatedApplication,
  tokenScopes: string[],
  sourceIp: string,
): Promise<void> {
  if (application.kind !== "agent") return;
  enforceSourceCidr(tenant, application, sourceIp);
  enforceScopeCeiling(application, tokenScopes.length);
  await enforceTokenBudget(tenant, application);
}

/** Agent guardrail: the source address must be inside `allowed_cidrs`. No-op for services. */
export function enforceSourceCidr(
  tenant: Tenant,
  application: AuthenticatedApplication,
  sourceIp: string,
): void {
  if (application.kind !== "agent") return;
  let ipAllowed: boolean;
  try {
    ipAllowed = ipInCidrs(sourceIp, application.allowedCidrs);
  } catch (err) {
    // A corrupt stored CIDR fails closed, with its own reason so operators can tell it apart.
    logger.error({ err, tenantId: tenant.id, applicationId: application.id }, "Bad allowed_cidrs");
    deny(OAUTH_ERRORS.UNAUTHORIZED_CLIENT, "Source address is not allowed", "cidr_invalid");
  }
  if (!ipAllowed) {
    deny(OAUTH_ERRORS.UNAUTHORIZED_CLIENT, "Source address is not allowed", "cidr_denied");
  }
}

function enforceScopeCeiling(application: AuthenticatedApplication, scopeCount: number): void {
  // shortcut: with `scope` omitted the whole grant counts, so an over-granted agent must request explicitly (intended least-privilege nudge).
  if (
    application.kind === "agent" &&
    application.maxScopesPerToken !== null &&
    scopeCount > application.maxScopesPerToken
  ) {
    deny(OAUTH_ERRORS.INVALID_SCOPE, "Too many scopes requested for one token", "scope_ceiling");
  }
}

/** Agent guardrail: 429 with Retry-After once the hourly token budget is spent. No-op for services. */
export async function enforceTokenBudget(
  tenant: Tenant,
  application: AuthenticatedApplication,
): Promise<void> {
  if (application.kind === "agent" && application.tokenBudgetPerHour !== null) {
    // shortcut: read is not serialised with the insert, so concurrent requests can overshoot by the in-flight count, and Retry-After then under-promises (only the oldest event ages out); a counter row would make both exact.
    const { count, retryAfterSeconds } = await countIssuedLastHour(tenant.id, application.id);
    if (count >= application.tokenBudgetPerHour) {
      const err = new OAuthError("too_many_requests", 429, "Hourly token budget exhausted");
      err.reason = "budget_exhausted";
      err.retryAfterSeconds = retryAfterSeconds;
      throw err;
    }
  }
}

/**
 * Issue a client-credentials access token for an already authenticated application, or open a
 * human approval when an agent asks for an `approval` scope.
 */
export async function issueToken(
  tenant: Tenant,
  application: AuthenticatedApplication,
  request: {
    audience: string;
    requestedScopes?: string[];
    taskId?: string;
    actorHint?: string;
    justification?: string;
  },
  ctx: { sourceIp: string },
): Promise<TokenResponse | PendingApproval> {
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

  // Guardrails first: a request that would fail anyway never reaches the human queue.
  await enforceAgentGuardrails(tenant, application, tokenScopes, ctx.sourceIp);

  if (application.kind === "agent") {
    const policies = await db
      .select({ agentPolicy: scopes.agentPolicy })
      .from(scopes)
      .where(
        and(
          eq(scopes.tenantId, tenant.id),
          eq(scopes.resourceId, resource.id),
          inArray(scopes.name, tokenScopes),
        ),
      );
    if (policies.some((p) => p.agentPolicy === "never")) {
      deny(
        OAUTH_ERRORS.INVALID_SCOPE,
        "Requested scope is not available to agents",
        "invalid_scope",
      );
    }
    // Mixed requests go pending as a whole: one token carries one scope string.
    if (policies.some((p) => p.agentPolicy === "approval")) {
      return createApprovalRequest(
        tenant,
        application,
        {
          resourceId: resource.id,
          audience: request.audience,
          scopes: tokenScopes,
          actorHint: request.actorHint,
          taskId: request.taskId,
          justification: request.justification,
        },
        ctx,
      );
    }
  }

  const ttl =
    application.tokenTtlSeconds ?? resource.tokenTtlSeconds ?? tenant.defaultTokenTtlSeconds;
  return signAndRecord(
    tenant,
    application,
    {
      resourceId: resource.id,
      audience: request.audience,
      scopes: tokenScopes,
      ttl,
      taskId: request.taskId,
    },
    ctx,
  );
}

/**
 * Redeem an approval (grant_type `urn:handsal:params:grant-type:approval`): exactly one
 * 300 s token per approved row. Unknown, foreign-tenant and other-application ids are all
 * `invalid_grant`.
 */
export async function redeemApproval(
  tenant: Tenant,
  application: AuthenticatedApplication,
  approvalId: string,
  ctx: { sourceIp: string },
): Promise<TokenResponse | PendingApproval> {
  if (tenant.status === "paused") {
    deny(OAUTH_ERRORS.INVALID_REQUEST, "tenant paused", "tenant_paused");
  }
  // Guardrails before the claim, so a refused poll never burns the approval.
  enforceSourceCidr(tenant, application, ctx.sourceIp);
  await enforceTokenBudget(tenant, application);

  const { claimed, current } = await claimApproval(tenant.id, application.id, approvalId);
  try {
    if (!claimed) {
      if (!current || (current.status === "approved" && current.consumedAt)) {
        deny(OAUTH_ERRORS.INVALID_GRANT, "Unknown or already used approval", "invalid_grant");
      }
      if (current.status === "denied") {
        deny(OAUTH_ERRORS.ACCESS_DENIED, "The approval was denied", "approval_denied");
      }
      if (current.status === "expired" || current.expiresAt <= new Date()) {
        deny(OAUTH_ERRORS.EXPIRED_TOKEN, "The approval has expired", "approval_expired");
      }
      return { approvalId: current.id, status: "pending" };
    }

    // A grant revoked or a resource disabled during the window voids the approval.
    // shortcut: denials and signing failures after the claim burn the approval; avoids a transaction held across key ops.
    const granted = await getGrantedScopesForAudience(tenant.id, application.id, claimed.audience);
    if (
      granted?.resource.status !== "active" ||
      granted.resource.id !== claimed.resourceId ||
      claimed.scopes.some((s) => !granted.scopeNames.includes(s))
    ) {
      deny(OAUTH_ERRORS.INVALID_GRANT, "Approved scopes are no longer granted", "invalid_grant");
    }
    // A scope demoted to `never` (or deleted) during the window voids the approval.
    const policies = await db
      .select({ agentPolicy: scopes.agentPolicy })
      .from(scopes)
      .where(
        and(
          eq(scopes.tenantId, tenant.id),
          eq(scopes.resourceId, claimed.resourceId),
          inArray(scopes.name, claimed.scopes),
        ),
      );
    if (
      policies.length !== claimed.scopes.length ||
      policies.some((p) => p.agentPolicy === "never")
    ) {
      deny(OAUTH_ERRORS.INVALID_GRANT, "Approved scopes are no longer allowed", "policy_changed");
    }
    enforceScopeCeiling(application, claimed.scopes.length);
  } catch (err) {
    // Stamp the denial event with what the row asked for; a poll body carries neither.
    if (err instanceof OAuthError && current) {
      err.eventTarget = { audience: current.audience, scopes: current.scopes };
    }
    throw err;
  }
  return signAndRecord(
    tenant,
    application,
    {
      resourceId: claimed.resourceId,
      audience: claimed.audience,
      scopes: claimed.scopes,
      ttl: DEFAULTS.APPROVAL_TOKEN_TTL_SECONDS,
      taskId: claimed.taskId ?? undefined,
      reason: "approval",
    },
    ctx,
  );
}

/** Delegation (RFC 8693): the token's `sub` is the subject, `act` names the acting agent chain. */
export interface Delegation {
  sub: string;
  act: Record<string, unknown>;
}

/** Sign the access token, record the `issued` event and touch `last_token_at`. */
export async function signAndRecord(
  tenant: Tenant,
  application: AuthenticatedApplication,
  t: {
    resourceId: string;
    audience: string;
    scopes: string[];
    ttl: number;
    taskId?: string;
    delegation?: Delegation;
    /** Event reason marking how the token was obtained (e.g. `approval`). */
    reason?: string;
  },
  ctx: { sourceIp: string },
): Promise<TokenResponse> {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + t.ttl;
  const jti = randomUUID();
  const scope = t.scopes.join(" ");

  const { kid, privateKeyPem } = await getActiveKey(tenant.id);
  const accessToken = await signAccessToken(privateKeyPem, kid, {
    iss: `${env.PUBLIC_URL}/t/${tenant.slug}`,
    sub: t.delegation?.sub ?? application.clientId,
    client_id: application.clientId,
    aud: t.audience,
    scope,
    tenant: tenant.slug,
    client_kind: application.kind,
    ...(t.taskId && { task_id: t.taskId }),
    ...(t.delegation && { act: t.delegation.act }),
    jti,
    iat,
    exp,
  });

  await recordTokenEvent({
    tenantId: tenant.id,
    applicationId: application.id,
    applicationClientId: application.clientId,
    resourceId: t.resourceId,
    audience: t.audience,
    outcome: "issued",
    reason: t.reason ?? null,
    scopes: t.scopes,
    jti,
    expiresAt: new Date(exp * 1000),
    sourceIp: ctx.sourceIp.slice(0, 45),
    taskId: t.taskId ?? null,
    actorSub: t.delegation?.sub.slice(0, 255) ?? null,
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

  return { access_token: accessToken, token_type: TOKEN_TYPES.BEARER, expires_in: t.ttl, scope };
}
