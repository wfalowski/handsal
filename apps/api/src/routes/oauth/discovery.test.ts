import { runMigrations } from "@handsal/db";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../app.js";
import { createResourceWithScopes, createTenant, truncateAll } from "../../test/factories.js";

const app = createApp({ readinessCheck: async () => {} });
const BASE = "https://test.example.com";
const AUTH = ["client_secret_basic", "client_secret_post", "private_key_jwt"];

beforeAll(async () => {
  await runMigrations();
});
beforeEach(async () => {
  await truncateAll();
});

const get = (slug: string, name = "openid-configuration") =>
  app.request(`/t/${slug}/.well-known/${name}`);

describe("discovery", () => {
  it("builds URLs from PUBLIC_URL + slug and returns the fixed fields", async () => {
    const t = await createTenant({ slug: "acme" });
    const res = await get(t.slug);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    expect(await res.json()).toEqual({
      issuer: `${BASE}/t/acme`,
      token_endpoint: `${BASE}/t/acme/oauth/token`,
      introspection_endpoint: `${BASE}/t/acme/oauth/introspect`,
      revocation_endpoint: `${BASE}/t/acme/oauth/revoke`,
      jwks_uri: `${BASE}/t/acme/.well-known/jwks.json`,
      grant_types_supported: [
        "client_credentials",
        "urn:handsal:params:grant-type:approval",
        "urn:ietf:params:oauth:grant-type:token-exchange",
      ],
      token_endpoint_auth_methods_supported: AUTH,
      introspection_endpoint_auth_methods_supported: AUTH,
      revocation_endpoint_auth_methods_supported: AUTH,
      response_types_supported: [],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_signing_alg_values_supported: ["ES256"],
    });
  });

  it("omits introspection_endpoint when disabled", async () => {
    const t = await createTenant({ introspectionEnabled: false });
    const body = await (await get(t.slug)).json();
    expect(body).not.toHaveProperty("introspection_endpoint");
    expect(body).toHaveProperty("revocation_endpoint");
  });

  it("serves identical bodies at both paths", async () => {
    const t = await createTenant();
    const a = await (await get(t.slug)).json();
    const b = await (await get(t.slug, "oauth-authorization-server")).json();
    expect(a).toEqual(b);
  });

  it("does not publish scope names", async () => {
    const t = await createTenant();
    await createResourceWithScopes(t.id, "https://a.io/x", ["b:read", "a:read"]);
    await createResourceWithScopes(t.id, "https://b.io/y", ["b:read", "c:read"]);
    const body = await (await get(t.slug)).json();
    expect(body).not.toHaveProperty("scopes_supported");
  });

  it("serves a paused tenant", async () => {
    const t = await createTenant({ status: "paused" });
    expect((await get(t.slug)).status).toBe(200);
  });

  it("404 JSON for unknown slug", async () => {
    const res = await get("nope");
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
  });
});
