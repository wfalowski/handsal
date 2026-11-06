import {
  approvalGrantSchema,
  CLIENT_ASSERTION_TYPES,
  DEFAULTS,
  GRANT_TYPES,
  OAUTH_ERRORS,
  tokenRequestSchema,
} from "@handsal/shared";
import { type Context, Hono, type MiddlewareHandler } from "hono";
import type { AppEnv } from "../../app.js";
import { env } from "../../env.js";
import { OAuthError } from "../../middleware/error-handler.js";
import { clientIdKey, ipKey, rateLimit } from "../../middleware/rate-limit.js";
import {
  type AuthenticatedApplication,
  assertionClientId,
  authenticateClient,
  authenticateClientAssertion,
} from "../../services/client-auth.service.js";
import { issueToken, redeemApproval } from "../../services/token.service.js";
import { recordTokenEvent } from "../../services/token-event.service.js";
import { getClientIp } from "../../utils/client-ip.js";
import { isFormUrlEncoded, parseBasicAuth } from "./helpers.js";

const WINDOW_MS = 60_000;

/** Parse a form-encoded body once into `c.var.formBody` (read by `clientIdKey` and the handler). */
export const parseFormBody: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (isFormUrlEncoded(c.req.header("content-type"))) {
    const raw = await c.req.parseBody({ all: true });
    const body: Record<string, string> = {};
    for (const [key, value] of Object.entries(raw)) {
      // Repeated parameters are rejected rather than collapsed to one value (RFC 6749 §3.2).
      if (Array.isArray(value)) {
        if (key === "resource") {
          throw new OAuthError(OAUTH_ERRORS.INVALID_TARGET, 400, "resource must not be repeated");
        }
        throw invalidRequest("Parameters must not be repeated");
      }
      if (typeof value === "string") body[key] = value;
    }
    c.set("formBody", body);
  }
  await next();
};

function invalidRequest(description: string): OAuthError {
  return new OAuthError(OAUTH_ERRORS.INVALID_REQUEST, 400, description);
}

/**
 * Authenticate the caller of a form-encoded endpoint (token, introspect, revoke):
 * a private_key_jwt assertion, or Basic/body credentials per the app's registered method.
 * Requires `parseFormBody` to have run.
 */
export async function authenticateFormClient(
  c: Context<AppEnv>,
): Promise<AuthenticatedApplication> {
  const body = c.var.formBody;
  if (!body) throw invalidRequest("Content-Type must be application/x-www-form-urlencoded");
  const basic = parseBasicAuth(c.req.header("Authorization"));
  const { client_assertion: assertion, client_assertion_type: assertionType } = body;
  if (assertion !== undefined || assertionType !== undefined) {
    if (assertion === undefined || assertionType === undefined) {
      throw invalidRequest("client_assertion and client_assertion_type must be sent together");
    }
    if (assertionType !== CLIENT_ASSERTION_TYPES.JWT_BEARER) {
      throw invalidRequest("Unsupported client_assertion_type");
    }
    // Bound checked before auth: a post-auth failure would burn the assertion's jti.
    if (!tokenRequestSchema.shape.client_assertion.safeParse(assertion).success) {
      throw invalidRequest("client_assertion is too long");
    }
    // RFC 6749 §2.3: a client must not use more than one authentication method.
    if (basic || body.client_secret !== undefined) {
      throw invalidRequest("Multiple client authentication methods");
    }
    const { application } = await authenticateClientAssertion(
      c.var.tenant,
      assertion,
      getClientIp(c),
      body.client_id,
    );
    return application;
  }
  // RFC 6749 §2.3: a client must not use more than one authentication method.
  if (basic && body.client_secret !== undefined) {
    throw invalidRequest("Multiple client authentication methods");
  }
  const clientId = basic?.clientId ?? body.client_id;
  const clientSecret = basic?.clientSecret ?? body.client_secret;
  if (!clientId || !clientSecret) {
    throw new OAuthError(OAUTH_ERRORS.INVALID_CLIENT, 401, "Client credentials are required");
  }
  const { application } = await authenticateClient(
    c.var.tenant,
    { clientId, clientSecret, viaBasic: basic !== null },
    getClientIp(c),
  );
  return application;
}

function splitScopes(scope: string | undefined): string[] {
  return scope?.split(" ").filter(Boolean) ?? [];
}

/**
 * `POST /t/:slug/oauth/token` (client_credentials, approval polling). Limits are injectable for
 * tests.
 */
export function createTokenRoutes({
  ipMax = env.RATE_LIMIT_TOKEN_IP_MAX,
  clientMax = env.RATE_LIMIT_TOKEN_CLIENT_MAX,
}: {
  ipMax?: number;
  clientMax?: number;
} = {}) {
  const token = new Hono<AppEnv>();

  token.post(
    "/",
    rateLimit({ keyFn: ipKey, max: ipMax, windowMs: WINDOW_MS, errorBody: "oauth" }),
    parseFormBody,
    rateLimit({ keyFn: clientIdKey, max: clientMax, windowMs: WINDOW_MS, errorBody: "oauth" }),
    async (c) => {
      const tenant = c.var.tenant;
      const body = c.var.formBody;
      const sourceIp = getClientIp(c);
      const basic = parseBasicAuth(c.req.header("Authorization"));
      const clientId =
        basic?.clientId ?? body?.client_id ?? assertionClientId(body?.client_assertion);
      let application: AuthenticatedApplication | undefined;
      const pending = (approvalId: string) =>
        c.json(
          {
            error: OAUTH_ERRORS.AUTHORIZATION_PENDING,
            error_description: "Waiting for human approval of one or more requested scopes",
            approval_id: approvalId,
            interval: DEFAULTS.APPROVAL_POLL_INTERVAL_SECONDS,
          },
          400,
        );

      try {
        if (!body) {
          throw invalidRequest("Content-Type must be application/x-www-form-urlencoded");
        }
        if (!body.grant_type) throw invalidRequest("grant_type is required");
        if (
          body.grant_type !== GRANT_TYPES.CLIENT_CREDENTIALS &&
          body.grant_type !== GRANT_TYPES.APPROVAL
        ) {
          throw new OAuthError(OAUTH_ERRORS.UNSUPPORTED_GRANT_TYPE, 400, "Unsupported grant_type");
        }

        application = await authenticateFormClient(c);
        c.header("Cache-Control", "no-store");
        c.header("Pragma", "no-cache");

        if (body.grant_type === GRANT_TYPES.APPROVAL) {
          const grant = approvalGrantSchema.safeParse(body);
          if (!grant.success) throw invalidRequest("approval_id is missing or invalid");
          const response = await redeemApproval(tenant, application, grant.data.approval_id, {
            sourceIp,
          });
          return "approvalId" in response ? pending(response.approvalId) : c.json(response);
        }

        // A missing or malformed resource is invalid_target, not a generic schema failure.
        if (!tokenRequestSchema.shape.resource.safeParse(body.resource).success) {
          const err = new OAuthError(
            OAUTH_ERRORS.INVALID_TARGET,
            400,
            body.resource ? "resource is invalid" : "resource is required",
          );
          err.reason = "invalid_target";
          throw err;
        }
        const parsed = tokenRequestSchema.safeParse(body);
        if (!parsed.success) throw invalidRequest("Invalid or missing required parameters");

        const response = await issueToken(
          tenant,
          application,
          {
            audience: parsed.data.resource,
            requestedScopes: splitScopes(parsed.data.scope),
            taskId: parsed.data.task_id,
            actorHint: parsed.data.actor_hint,
            justification: parsed.data.justification,
          },
          { sourceIp },
        );
        // Returned, not thrown: the body carries approval_id/interval and the event is `pending`.
        return "approvalId" in response ? pending(response.approvalId) : c.json(response);
      } catch (err) {
        if (err instanceof OAuthError) {
          await recordTokenEvent({
            tenantId: tenant.id,
            applicationId: application?.id ?? null,
            applicationClientId: clientId?.slice(0, 32) ?? null,
            audience: body?.resource?.slice(0, 512) ?? null,
            outcome: "denied",
            reason: (err.reason ?? err.errorCode).slice(0, 64),
            scopes: splitScopes(body?.scope),
            sourceIp: sourceIp.slice(0, 45),
            taskId: body?.task_id?.slice(0, 128) ?? null,
          });
        }
        throw err;
      }
    },
  );

  return token;
}
