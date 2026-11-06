import { GRANT_TYPES, OAUTH_ERRORS, tokenRequestSchema } from "@handsal/shared";
import { Hono, type MiddlewareHandler } from "hono";
import type { AppEnv } from "../../app.js";
import { env } from "../../env.js";
import { OAuthError } from "../../middleware/error-handler.js";
import { clientIdKey, ipKey, rateLimit } from "../../middleware/rate-limit.js";
import {
  type AuthenticatedApplication,
  authenticateClient,
} from "../../services/client-auth.service.js";
import { issueToken } from "../../services/token.service.js";
import { recordTokenEvent } from "../../services/token-event.service.js";
import { getClientIp } from "../../utils/client-ip.js";
import { isFormUrlEncoded, parseBasicAuth } from "./helpers.js";

const WINDOW_MS = 60_000;

/** Parse a form-encoded body once into `c.var.formBody` (read by `clientIdKey` and the handler). */
const parseFormBody: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (isFormUrlEncoded(c.req.header("content-type"))) {
    const raw = await c.req.parseBody();
    const body: Record<string, string> = {};
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === "string") body[key] = value;
    }
    c.set("formBody", body);
  }
  await next();
};

function invalidRequest(description: string): OAuthError {
  return new OAuthError(OAUTH_ERRORS.INVALID_REQUEST, 400, description);
}

function splitScopes(scope: string | undefined): string[] {
  return scope?.split(" ").filter(Boolean) ?? [];
}

/** `POST /t/:slug/oauth/token` (client_credentials). Limits are injectable for tests. */
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
      const clientId = basic?.clientId ?? body?.client_id;
      let application: AuthenticatedApplication | undefined;

      try {
        if (!body) {
          throw invalidRequest("Content-Type must be application/x-www-form-urlencoded");
        }
        if (!body.grant_type) throw invalidRequest("grant_type is required");
        if (body.grant_type !== GRANT_TYPES.CLIENT_CREDENTIALS) {
          throw new OAuthError(OAUTH_ERRORS.UNSUPPORTED_GRANT_TYPE, 400, "Unsupported grant_type");
        }

        // RFC 6749 §2.3: a client must not use more than one authentication method.
        if (basic && body.client_secret !== undefined) {
          throw invalidRequest("Multiple client authentication methods");
        }
        const clientSecret = basic?.clientSecret ?? body.client_secret;
        if (!clientId || !clientSecret) {
          throw new OAuthError(OAUTH_ERRORS.INVALID_CLIENT, 401, "Client credentials are required");
        }
        ({ application } = await authenticateClient(
          tenant,
          { clientId, clientSecret, viaBasic: basic !== null },
          sourceIp,
        ));

        if (!body.resource) {
          const err = new OAuthError(OAUTH_ERRORS.INVALID_TARGET, 400, "resource is required");
          err.reason = "invalid_target";
          throw err;
        }
        const parsed = tokenRequestSchema.safeParse(body);
        if (!parsed.success) throw invalidRequest("Invalid or missing required parameters");

        const response = await issueToken(
          tenant,
          application,
          { audience: parsed.data.resource, requestedScopes: splitScopes(parsed.data.scope) },
          { sourceIp },
        );
        c.header("Cache-Control", "no-store");
        c.header("Pragma", "no-cache");
        return c.json(response);
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
          });
        }
        throw err;
      }
    },
  );

  return token;
}
