import { Hono } from "hono";
import type { AppEnv } from "../../app.js";
import { tenantResolver } from "../../middleware/tenant-resolver.js";
import { createDiscoveryRoutes } from "./discovery.js";
import { createIntrospectRoutes } from "./introspect.js";
import { createJwksRoutes } from "./jwks.js";
import { createRevokeRoutes } from "./revoke.js";
import { createTokenRoutes } from "./token.js";

// Mounted at /t/:slug. Issuer routes see `c.var.tenant`. The wildcard used to cover
// every /t/<segment>/... path, so a refresh of /t/<tenantId>/applications/<appId>
// looked the UUID up as a slug and returned "unknown tenant".
export const oauthRoutes = new Hono<AppEnv>();

oauthRoutes.use("/oauth/*", tenantResolver);
oauthRoutes.use("/.well-known/*", tenantResolver);
oauthRoutes.route("/oauth/token", createTokenRoutes());
oauthRoutes.route("/.well-known", createDiscoveryRoutes());
oauthRoutes.route("/.well-known", createJwksRoutes());
oauthRoutes.route("/oauth/introspect", createIntrospectRoutes());
oauthRoutes.route("/oauth/revoke", createRevokeRoutes());
