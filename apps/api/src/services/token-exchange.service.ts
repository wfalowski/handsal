import { db, scopes } from "@handsal/db";
import {
  ISSUED_TOKEN_TYPE,
  MAY_ACT_FOR,
  OAUTH_ERRORS,
  SUB_KINDS,
  type SubKind,
  TOKEN_TYPES,
} from "@handsal/shared";
import { and, eq, inArray } from "drizzle-orm";
import { createRemoteJWKSet, customFetch, decodeJwt, type JWTPayload, jwtVerify } from "jose";
import { pinnedFetch } from "../utils/outbound-url.js";
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
// Bounded: jwksUri is tenant-admin controlled, so FIFO eviction like privateKeyCache in utils/jwt.ts.
const MAX_REMOTE_JWKS = 100;
const remoteJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getRemoteJwks(tenantId: string, jwksUri: string) {
  const key = `${tenantId} ${jwksUri}`;
  let set = remoteJwks.get(key);
  if (!set) {
    set = createRemoteJWKSet(new URL(jwksUri), {
      // No redirects: a 3xx could send the fetch past the jwksUri destination guard.
      [customFetch]: (url, options) => pinnedFetch(url, { ...options, redirect: "error" }),
    });
    if (remoteJwks.size >= MAX_REMOTE_JWKS) {
      const oldest = remoteJwks.keys().next().value;
      if (oldest !== undefined) remoteJwks.delete(oldest);
    }
    remoteJwks.set(key, set);
  }
  return set;
}

/** Most `act` levels an issued token may carry (each exchange of an exchanged token adds one). */
const MAX_ACT_DEPTH = 3;

interface Subject {
  /** `may_act_for` member that admits this subject. */
  classes: string[];
  sub: string;
  /** What `sub` is, sticky across re-exchanges: where the subject chain originated. */
  subKind: SubKind;
  /** Only Handsal-issued subjects contribute a nested `act`; an IdP's `act` is not trusted. */
  act: Record<string, unknown> | undefined;
  /** null: the subject carries no scope claim at all. */
  scopes: string[] | null;
  /** Subject credential expiry (seconds). The issued token must not outlive it. */
  exp: number;
}

function scopesOf(payload: JWTPayload): string[] | null {
  if (typeof payload.scope === "string") return payload.scope.split(" ").filter(Boolean);
  if (Array.isArray(payload.scope)) return payload.scope.filter((s) => typeof s === "string");
  if (Array.isArray(payload.scp)) return payload.scp.filter((s) => typeof s === "string");
  return null;
}

function actOf(payload: JWTPayload): Record<string, unknown> | undefined {
  const act = payload.act;
  return act && typeof act === "object" && !Array.isArray(act)
    ? (act as Record<string, unknown>)
    : undefined;
}

function actDepth(act: Record<string, unknown> | undefined): number {
  let depth = 0;
  for (let a: unknown = act; a && typeof a === "object"; a = (a as { act?: unknown }).act) depth++;
  return depth;
}

/** `may_act_for` members that admit a subject of this kind. */
function classesOf(subKind: SubKind): string[] {
  if (subKind === SUB_KINDS.USER) return [MAY_ACT_FOR.USERS];
  // `tenant` admits any client of the tenant, so it also covers service subjects.
  if (subKind === SUB_KINDS.SERVICE) return [MAY_ACT_FOR.SERVICES, MAY_ACT_FOR.TENANT];
  return [MAY_ACT_FOR.TENANT];
}

const SUB_KIND_VALUES: readonly unknown[] = Object.values(SUB_KINDS);

/**
 * Handsal token of this tenant first, then the tenant's external IdP. Null when neither verifies.
 * `subject_token_type` is validated by the schema but not used to branch: both paths are tried,
 * and a mis-declared type cannot widen what a token verifies as (accepted, review 6.4 #9).
 */
async function verifySubject(
  tenant: Tenant,
  token: string,
  audience: string,
): Promise<Subject | null> {
  const introspected = await introspectToken(tenant, token);
  if (introspected.active) {
    // Pinned to the target: a token for another resource is not rebound to this one.
    if (introspected.aud !== audience) return null;
    // Signature already verified by introspectToken; decode only to read `act`/`sub_kind`.
    const payload = decodeJwt(token);
    const subKind = SUB_KIND_VALUES.includes(payload.sub_kind)
      ? (payload.sub_kind as SubKind)
      : introspected.client_kind === "service"
        ? SUB_KINDS.SERVICE
        : SUB_KINDS.AGENT;
    return {
      classes: classesOf(subKind),
      sub: introspected.sub,
      subKind,
      act: actOf(payload),
      scopes: scopesOf(payload),
      exp: introspected.exp,
    };
  }

  const idp = tenant.externalIdp;
  if (!idp) return null;
  try {
    const { payload } = await jwtVerify(token, getRemoteJwks(tenant.id, idp.jwksUri), {
      issuer: idp.issuer,
      audience: idp.audience,
      algorithms: ["RS256", "PS256", "ES256", "ES384", "EdDSA"],
      // No revocation for external subjects: `exp` is the only bound on the credential.
      requiredClaims: ["exp"],
      clockTolerance: 5,
    });
    if (typeof payload.sub !== "string" || !payload.sub || typeof payload.exp !== "number") {
      return null;
    }
    return {
      classes: classesOf(SUB_KINDS.USER),
      sub: payload.sub,
      subKind: SUB_KINDS.USER,
      act: undefined,
      // Matched by name against the agent's scopes on the target resource (docs/integration.md §8).
      scopes: scopesOf(payload),
      exp: payload.exp,
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
  const subject = await verifySubject(tenant, request.subjectToken, request.audience);
  if (!subject) {
    deny(OAUTH_ERRORS.INVALID_GRANT, "Invalid subject_token", "invalid_subject_token");
  }
  if (actDepth(subject.act) >= MAX_ACT_DEPTH) {
    deny(OAUTH_ERRORS.INVALID_GRANT, "Delegation chain too deep", "act_chain_too_deep");
  }
  // unauthorized_client after verification tells an authenticated client of this tenant the
  // token is live; accepted as a narrow oracle (review 6.4 #10).
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

  const configuredTtl =
    application.tokenTtlSeconds ?? resource.tokenTtlSeconds ?? tenant.defaultTokenTtlSeconds;
  // Whole seconds left on the subject. No TTL_MIN floor: a 20s subject yields a ~20s token.
  const subjectTtl = Math.floor(subject.exp - Date.now() / 1000);
  if (subjectTtl < 1) {
    deny(OAUTH_ERRORS.INVALID_GRANT, "Invalid subject_token", "invalid_subject_token");
  }
  const ttl = Math.min(configuredTtl, subjectTtl);
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
      delegation: { sub: subject.sub, subKind: subject.subKind, act },
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
