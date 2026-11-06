import { db, scopes } from "@handsal/db";
import { ISSUED_TOKEN_TYPE, MAY_ACT_FOR, OAUTH_ERRORS, TOKEN_TYPES } from "@handsal/shared";
import { and, eq, inArray } from "drizzle-orm";
import { createRemoteJWKSet, decodeJwt, type JWTPayload, jwtVerify } from "jose";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import { getGrantedScopesForAudience } from "./grant.service.js";
import { introspectToken } from "./introspection.service.js";
import type { Tenant } from "./tenant.service.js";
import { deny, enforceAgentGuardrails, signAndRecord } from "./token.service.js";

export interface TokenExchangeResponse {
  access_token: string;
  issued_token_type: typeof ISSUED_TOKEN_TYPE;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

// jose's remote set caches keys and rate-limits refetches (cooldown) itself.
// shortcut: entries are never evicted; bounded by tenants × configured jwksUri changes, fine until IdP churn is high.
const remoteJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getRemoteJwks(tenantId: string, jwksUri: string) {
  const key = `${tenantId} ${jwksUri}`;
  let set = remoteJwks.get(key);
  if (!set) {
    set = createRemoteJWKSet(new URL(jwksUri));
    remoteJwks.set(key, set);
  }
  return set;
}

interface Subject {
  /** `may_act_for` member that admits this subject. */
  classes: string[];
  sub: string;
  act: Record<string, unknown> | undefined;
  /** null: the subject carries no scope claim at all. */
  scopes: string[] | null;
}

function scopesOf(payload: JWTPayload): string[] | null {
  if (typeof payload.scope === "string") return payload.scope.split(" ").filter(Boolean);
  if (Array.isArray(payload.scp)) return payload.scp.filter((s) => typeof s === "string");
  return null;
}

function actOf(payload: JWTPayload): Record<string, unknown> | undefined {
  const act = payload.act;
  return act && typeof act === "object" && !Array.isArray(act)
    ? (act as Record<string, unknown>)
    : undefined;
}

/** Handsal token of this tenant first, then the tenant's external IdP. Null when neither verifies. */
async function verifySubject(tenant: Tenant, token: string): Promise<Subject | null> {
  const introspected = await introspectToken(tenant, token);
  if (introspected.active) {
    // Signature already verified by introspectToken; decode only to read `act`.
    const payload = decodeJwt(token);
    return {
      // `tenant` admits any client of the tenant, so it also covers service subjects.
      classes:
        introspected.client_kind === "service"
          ? [MAY_ACT_FOR.SERVICES, MAY_ACT_FOR.TENANT]
          : [MAY_ACT_FOR.TENANT],
      sub: introspected.sub,
      act: actOf(payload),
      scopes: scopesOf(payload),
    };
  }

  const idp = tenant.externalIdp;
  if (!idp) return null;
  try {
    const { payload } = await jwtVerify(token, getRemoteJwks(tenant.id, idp.jwksUri), {
      issuer: idp.issuer,
      audience: idp.audience,
      clockTolerance: 60,
    });
    if (typeof payload.sub !== "string" || !payload.sub) return null;
    return {
      classes: [MAY_ACT_FOR.USERS],
      sub: payload.sub,
      act: actOf(payload),
      scopes: scopesOf(payload),
    };
  } catch {
    return null;
  }
}

/**
 * RFC 8693 token exchange: an agent trades a subject token (Handsal access token of this
 * tenant, or the tenant's external IdP JWT) for an access token on `audience` that carries
 * `sub` = the subject and `act` = the agent.
 */
export async function exchangeToken(
  tenant: Tenant,
  application: AuthenticatedApplication,
  request: { subjectToken: string; audience: string; requestedScopes?: string[]; taskId?: string },
  ctx: { sourceIp: string },
): Promise<TokenExchangeResponse> {
  if (tenant.status === "paused") {
    deny(OAUTH_ERRORS.INVALID_REQUEST, "tenant paused", "tenant_paused");
  }
  if (application.kind !== "agent" || application.mayActFor.length === 0) {
    deny(
      OAUTH_ERRORS.UNAUTHORIZED_CLIENT,
      "Client may not use token exchange",
      "exchange_not_allowed",
    );
  }

  // One description for every verification failure: no oracle on which check failed.
  const subject = await verifySubject(tenant, request.subjectToken);
  if (!subject) {
    deny(OAUTH_ERRORS.INVALID_GRANT, "Invalid subject_token", "invalid_subject_token");
  }
  if (!subject.classes.some((c) => application.mayActFor.includes(c))) {
    deny(
      OAUTH_ERRORS.UNAUTHORIZED_CLIENT,
      "Client may not act for this subject",
      "may_act_for_denied",
    );
  }

  const granted = await getGrantedScopesForAudience(tenant.id, application.id, request.audience);
  if (granted?.resource.status !== "active") {
    deny(OAUTH_ERRORS.INVALID_TARGET, "Unknown or unauthorized resource", "invalid_target");
  }
  const { resource, scopeNames } = granted;

  let base = scopeNames;
  if (application.delegationScopeMode === "intersection") {
    const subjectScopes = subject.scopes;
    base = subjectScopes ? scopeNames.filter((s) => subjectScopes.includes(s)) : [];
    if (base.length === 0) {
      deny(OAUTH_ERRORS.INVALID_SCOPE, "No scopes shared with the subject", "invalid_scope");
    }
  }
  const requested = request.requestedScopes?.length ? [...new Set(request.requestedScopes)] : null;
  if (requested?.some((s) => !base.includes(s))) {
    deny(OAUTH_ERRORS.INVALID_SCOPE, "Requested scope is not granted", "invalid_scope");
  }
  const tokenScopes = requested ?? base;

  await enforceAgentGuardrails(tenant, application, tokenScopes, ctx.sourceIp);

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
    deny(OAUTH_ERRORS.INVALID_SCOPE, "Requested scope is not available to agents", "invalid_scope");
  }
  // Not queued: a later approval would mint a token from a subject credential no longer checked.
  if (policies.some((p) => p.agentPolicy === "approval")) {
    deny(
      OAUTH_ERRORS.INVALID_SCOPE,
      "scope requires human approval; request it with the approval grant",
      "approval_required",
    );
  }

  const ttl =
    application.tokenTtlSeconds ?? resource.tokenTtlSeconds ?? tenant.defaultTokenTtlSeconds;
  // Most recent actor outermost (RFC 8693 §4.1).
  const act = subject.act
    ? { sub: application.clientId, act: subject.act }
    : { sub: application.clientId };
  const issued = await signAndRecord(
    tenant,
    application,
    {
      resourceId: resource.id,
      audience: request.audience,
      scopes: tokenScopes,
      ttl,
      taskId: request.taskId,
      delegation: { sub: subject.sub, act },
    },
    ctx,
  );
  return {
    access_token: issued.access_token,
    issued_token_type: ISSUED_TOKEN_TYPE,
    token_type: TOKEN_TYPES.BEARER,
    expires_in: issued.expires_in,
    scope: issued.scope,
  };
}
