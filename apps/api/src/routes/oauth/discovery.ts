import { GRANT_TYPES } from "@handsal/shared";
import { type Context, Hono } from "hono";
import type { AppEnv } from "../../app.js";
import { env } from "../../env.js";

const AUTH_METHODS = ["client_secret_basic", "client_secret_post", "private_key_jwt"];

/** RFC 8414 / OIDC discovery document, served at both `.well-known` names. Mounted at `/.well-known`. */
export function createDiscoveryRoutes() {
  const routes = new Hono<AppEnv>();

  const handler = (c: Context<AppEnv>) => {
    const tenant = c.var.tenant;
    const issuer = `${env.PUBLIC_URL}/t/${tenant.slug}`;
    c.header("Cache-Control", "public, max-age=300");
    return c.json({
      issuer,
      token_endpoint: `${issuer}/oauth/token`,
      ...(tenant.introspectionEnabled && { introspection_endpoint: `${issuer}/oauth/introspect` }),
      revocation_endpoint: `${issuer}/oauth/revoke`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      grant_types_supported: [
        GRANT_TYPES.CLIENT_CREDENTIALS,
        GRANT_TYPES.APPROVAL,
        GRANT_TYPES.TOKEN_EXCHANGE,
      ],
      token_endpoint_auth_methods_supported: AUTH_METHODS,
      introspection_endpoint_auth_methods_supported: AUTH_METHODS,
      revocation_endpoint_auth_methods_supported: AUTH_METHODS,
      response_types_supported: [],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_signing_alg_values_supported: ["ES256"],
    });
  };

  routes.get("/openid-configuration", handler);
  routes.get("/oauth-authorization-server", handler);
  return routes;
}
