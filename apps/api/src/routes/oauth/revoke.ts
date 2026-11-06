import { OAUTH_ERRORS, revokeRequestSchema } from "@handsal/shared";
import { Hono } from "hono";
import type { AppEnv } from "../../app.js";
import { env } from "../../env.js";
import { OAuthError } from "../../middleware/error-handler.js";
import { clientIdKey, ipKey, rateLimit } from "../../middleware/rate-limit.js";
import { revokeToken } from "../../services/revocation.service.js";
import { getClientIp } from "../../utils/client-ip.js";
import { authenticateFormClient, parseFormBody } from "./token.js";

const WINDOW_MS = 60_000;

/** `POST /t/:slug/oauth/revoke` (RFC 7009). 200 with an empty body for any token. */
export function createRevokeRoutes({
  ipMax = env.RATE_LIMIT_REVOKE_IP_MAX,
  clientMax = env.RATE_LIMIT_REVOKE_CLIENT_MAX,
}: {
  ipMax?: number;
  clientMax?: number;
} = {}) {
  const revoke = new Hono<AppEnv>();

  revoke.post(
    "/",
    rateLimit({ keyFn: ipKey, max: ipMax, windowMs: WINDOW_MS, errorBody: "oauth" }),
    parseFormBody,
    rateLimit({ keyFn: clientIdKey, max: clientMax, windowMs: WINDOW_MS, errorBody: "oauth" }),
    async (c) => {
      const application = await authenticateFormClient(c);

      const parsed = revokeRequestSchema.safeParse(c.var.formBody);
      if (!parsed.success) {
        throw new OAuthError(OAUTH_ERRORS.INVALID_REQUEST, 400, "token is required");
      }

      await revokeToken(c.var.tenant, application, parsed.data.token, {
        sourceIp: getClientIp(c),
      });
      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.body(null, 200);
    },
  );

  return revoke;
}
