import { OAUTH_ERRORS } from "@handsal/shared";
import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.js";
import { getTenantBySlug } from "../services/tenant.service.js";
import { OAuthError } from "./error-handler.js";

/** Loads the tenant named by the `:slug` path param into `c.var.tenant`; 404 when unknown. */
export const tenantResolver: MiddlewareHandler<AppEnv> = async (c, next) => {
  const slug = c.req.param("slug");
  const tenant = slug ? await getTenantBySlug(slug) : null;
  if (!tenant) throw new OAuthError(OAUTH_ERRORS.INVALID_REQUEST, 404, "unknown tenant");
  c.set("tenant", tenant);
  await next();
};
