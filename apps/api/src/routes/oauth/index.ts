import { Hono } from "hono";
import type { AppEnv } from "../../app.js";
import { tenantResolver } from "../../middleware/tenant-resolver.js";
import { createTokenRoutes } from "./token.js";

// Mounted at /t/:slug. Every route below sees `c.var.tenant`.
export const oauthRoutes = new Hono<AppEnv>();

oauthRoutes.use("*", tenantResolver);
oauthRoutes.route("/oauth/token", createTokenRoutes());
