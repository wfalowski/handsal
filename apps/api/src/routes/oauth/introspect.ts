import { introspectRequestSchema, OAUTH_ERRORS } from "@handsal/shared";
import { Hono } from "hono";
import type { AppEnv } from "../../app.js";
import { env } from "../../env.js";
import { OAuthError } from "../../middleware/error-handler.js";
import { clientIdKey, ipKey, rateLimit } from "../../middleware/rate-limit.js";
import { introspectToken } from "../../services/introspection.service.js";
import { authenticateFormClient, parseFormBody } from "./token.js";

const WINDOW_MS = 60_000;

/** `POST /t/:slug/oauth/introspect` (RFC 7662). Any authenticated client of the tenant may call it. */
export function createIntrospectRoutes({
  ipMax = env.RATE_LIMIT_INTROSPECT_IP_MAX,
  clientMax = env.RATE_LIMIT_INTROSPECT_CLIENT_MAX,
}: {
  ipMax?: number;
  clientMax?: number;
} = {}) {
  const introspect = new Hono<AppEnv>();

  introspect.post(
    "/",
    rateLimit({ keyFn: ipKey, max: ipMax, windowMs: WINDOW_MS, errorBody: "oauth" }),
    parseFormBody,
    rateLimit({ keyFn: clientIdKey, max: clientMax, windowMs: WINDOW_MS, errorBody: "oauth" }),
    async (c) => {
      const tenant = c.var.tenant;
      // Authenticate first so unauthenticated callers cannot probe tenant configuration.
      await authenticateFormClient(c);
      if (!tenant.introspectionEnabled) {
        throw new OAuthError(OAUTH_ERRORS.INVALID_REQUEST, 404, "introspection disabled");
      }

      const parsed = introspectRequestSchema.safeParse(c.var.formBody);
      if (!parsed.success) {
        throw new OAuthError(OAUTH_ERRORS.INVALID_REQUEST, 400, "token is required");
      }

      const result = await introspectToken(tenant, parsed.data.token);
      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json(result);
    },
  );

  return introspect;
}
