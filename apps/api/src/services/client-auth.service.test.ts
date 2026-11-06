import { applicationKeys, applications, db, pool, runMigrations } from "@handsal/db";
import { OAUTH_ERRORS } from "@handsal/shared";
import { eq } from "drizzle-orm";
import { generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { OAuthError } from "../middleware/error-handler.js";
import {
  createApplication,
  createApplicationKey,
  createTenant,
  signClientAssertion,
  truncateAll,
} from "../test/factories.js";
import { MemoryStore } from "../utils/store.js";
import { rotateSecret, setApplicationStatus } from "./application.service.js";
import {
  assertionClientId,
  authenticateClient,
  authenticateClientAssertion,
} from "./client-auth.service.js";

const IP = "203.0.113.7";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

async function failureReason(promise: Promise<unknown>): Promise<string | undefined> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(OAuthError);
  const oauthErr = err as OAuthError;
  expect(oauthErr.errorCode).toBe(OAUTH_ERRORS.INVALID_CLIENT);
  expect(oauthErr.statusCode).toBe(401);
  expect(oauthErr.errorDescription).toBe("Invalid client credentials");
  return oauthErr.reason;
}

describe("authenticateClient", () => {
  it("authenticates a basic client and returns the application without hashes", async () => {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id);

    const result = await authenticateClient(
      tenant,
      { clientId: application.clientId, clientSecret, viaBasic: true },
      IP,
    );

    expect(result.application.id).toBe(application.id);
    expect(result.application).not.toHaveProperty("clientSecretHash");
    expect(result.application).not.toHaveProperty("previousSecretHash");
  });

  it("authenticates a post client via body credentials", async () => {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "client_secret_post",
    });
    const creds = { clientId: application.clientId, clientSecret, viaBasic: false };
    await expect(authenticateClient(tenant, creds, IP)).resolves.toBeDefined();
  });

  it("rejects an unknown client_id and a client of another tenant as unknown_client", async () => {
    const tenant = await createTenant();
    const other = await createTenant();
    const { application, clientSecret } = await createApplication(other.id);

    expect(
      await failureReason(
        authenticateClient(
          tenant,
          { clientId: "app_aaaaaaaaaaaaaaaaaaaa", clientSecret, viaBasic: true },
          IP,
        ),
      ),
    ).toBe("unknown_client");
    expect(
      await failureReason(
        authenticateClient(
          tenant,
          { clientId: application.clientId, clientSecret, viaBasic: true },
          IP,
        ),
      ),
    ).toBe("unknown_client");
  });

  it("rejects a method mismatch in both directions", async () => {
    const tenant = await createTenant();
    const basicApp = await createApplication(tenant.id);
    const postApp = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "client_secret_post",
    });

    expect(
      await failureReason(
        authenticateClient(
          tenant,
          {
            clientId: basicApp.application.clientId,
            clientSecret: basicApp.clientSecret,
            viaBasic: false,
          },
          IP,
        ),
      ),
    ).toBe("auth_method_mismatch");
    expect(
      await failureReason(
        authenticateClient(
          tenant,
          {
            clientId: postApp.application.clientId,
            clientSecret: postApp.clientSecret,
            viaBasic: true,
          },
          IP,
        ),
      ),
    ).toBe("auth_method_mismatch");
  });

  it("rejects a wrong secret as bad_secret", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id);
    expect(
      await failureReason(
        authenticateClient(
          tenant,
          { clientId: application.clientId, clientSecret: "hs_wrong", viaBasic: true },
          IP,
        ),
      ),
    ).toBe("bad_secret");
  });

  it("rejects a disabled client with client_disabled only once the secret verified", async () => {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id);
    await setApplicationStatus(tenant.id, application.id, "disabled");

    expect(
      await failureReason(
        authenticateClient(
          tenant,
          { clientId: application.clientId, clientSecret, viaBasic: true },
          IP,
        ),
      ),
    ).toBe("client_disabled");
    expect(
      await failureReason(
        authenticateClient(
          tenant,
          { clientId: application.clientId, clientSecret: "hs_wrong", viaBasic: true },
          IP,
        ),
      ),
    ).toBe("bad_secret");
  });

  describe("secret rotation grace (Review Focus 2)", () => {
    async function rotated() {
      const tenant = await createTenant();
      const { application, clientSecret: oldSecret } = await createApplication(tenant.id);
      const { clientSecret: newSecret } = await rotateSecret(tenant.id, application.id, 3600);
      const auth = (clientSecret: string) =>
        authenticateClient(
          tenant,
          { clientId: application.clientId, clientSecret, viaBasic: true },
          IP,
        );
      const setExpiry = (offsetMs: number) =>
        db
          .update(applications)
          .set({ previousSecretExpiresAt: new Date(Date.now() + offsetMs) })
          .where(eq(applications.id, application.id));
      return { oldSecret, newSecret, auth, setExpiry };
    }

    it("old secret works one second before expiry; new secret works", async () => {
      const { oldSecret, newSecret, auth, setExpiry } = await rotated();
      await setExpiry(1000);
      await expect(auth(oldSecret)).resolves.toBeDefined();
      await expect(auth(newSecret)).resolves.toBeDefined();
    });

    it("old secret fails one second after expiry; new secret still works", async () => {
      const { oldSecret, newSecret, auth, setExpiry } = await rotated();
      await setExpiry(-1000);
      expect(await failureReason(auth(oldSecret))).toBe("bad_secret");
      await expect(auth(newSecret)).resolves.toBeDefined();
    });
  });
});

describe("authenticateClientAssertion (private_key_jwt)", () => {
  async function setup() {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "private_key_jwt",
    });
    const { key, privateKey } = await createApplicationKey(tenant.id, application.id);
    const sign = (over: Partial<Parameters<typeof signClientAssertion>[1]> = {}) =>
      signClientAssertion(privateKey, {
        clientId: application.clientId,
        kid: key.kid,
        tenantSlug: tenant.slug,
        ...over,
      });
    const auth = async (assertion: string | Promise<string>, claimedClientId?: string) =>
      authenticateClientAssertion(tenant, await assertion, IP, claimedClientId);
    return { tenant, application, key, sign, auth };
  }

  const now = () => Math.floor(Date.now() / 1000);

  it("accepts an assertion signed by an active key and strips secret hashes", async () => {
    const { application, sign, auth } = await setup();
    const { application: result } = await auth(sign());
    expect(result.id).toBe(application.id);
    expect(result).not.toHaveProperty("clientSecretHash");
    expect(assertionClientId(await sign())).toBe(application.clientId);
  });

  it("rejects aud = issuer instead of the token endpoint", async () => {
    const { tenant, sign, auth } = await setup();
    const aud = `https://test.example.com/t/${tenant.slug}`;
    expect(await failureReason(auth(sign({ claims: { aud } })))).toBe("bad_assertion");
  });

  it("rejects a replayed jti", async () => {
    const { sign, auth } = await setup();
    const assertion = await sign();
    await expect(auth(assertion)).resolves.toBeDefined();
    expect(await failureReason(auth(assertion))).toBe("assertion_replayed");
  });

  it("rejects exp beyond the max lifetime, and an expired assertion", async () => {
    const { sign, auth } = await setup();
    expect(await failureReason(auth(sign({ claims: { exp: now() + 600 } })))).toBe("bad_assertion");
    const expired = sign({ claims: { iat: now() - 240, exp: now() - 120 } });
    expect(await failureReason(auth(expired))).toBe("assertion_expired");
  });

  it("allows the clock tolerance on top of the max lifetime", async () => {
    const { sign, auth } = await setup();
    // A client clock 30 s fast signing exp = its now + 300.
    await expect(
      auth(sign({ claims: { iat: now() + 30, exp: now() + 330 } })),
    ).resolves.toBeDefined();
    expect(await failureReason(auth(sign({ claims: { exp: now() + 400 } })))).toBe("bad_assertion");
  });

  it("reports a future nbf as assertion_not_yet_valid", async () => {
    const { sign, auth } = await setup();
    expect(await failureReason(auth(sign({ claims: { nbf: now() + 120 } })))).toBe(
      "assertion_not_yet_valid",
    );
  });

  it("rejects a jti that is empty, too long or not a string", async () => {
    const { sign, auth } = await setup();
    await expect(auth(sign({ claims: { jti: "j".repeat(128) } }))).resolves.toBeDefined();
    for (const jti of ["", "j".repeat(129), 5, { a: 1 }] as unknown as string[]) {
      expect(await failureReason(auth(sign({ claims: { jti } })))).toBe("bad_assertion");
    }
  });

  it("rejects a non-string iss equal to sub", async () => {
    const { sign, auth } = await setup();
    const claims = { iss: 5, sub: 5 } as unknown as { iss: string; sub: string };
    expect(assertionClientId(await sign({ claims }))).toBeUndefined();
    expect(await failureReason(auth(sign({ claims })))).toBe("bad_assertion");
  });

  it("rejects missing jti or exp, and iat in the future", async () => {
    const { sign, auth } = await setup();
    expect(await failureReason(auth(sign({ claims: { jti: undefined } })))).toBe("bad_assertion");
    expect(await failureReason(auth(sign({ claims: { exp: undefined } })))).toBe("bad_assertion");
    expect(await failureReason(auth(sign({ claims: { iat: now() + 120 } })))).toBe("bad_assertion");
  });

  it("rejects iss !== sub", async () => {
    const { sign, auth } = await setup();
    expect(await failureReason(auth(sign({ claims: { sub: "someone-else" } })))).toBe(
      "bad_assertion",
    );
  });

  it("rejects a kid belonging to another application's key", async () => {
    const { tenant, sign, auth } = await setup();
    const other = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "private_key_jwt",
    });
    const { key: otherKey } = await createApplicationKey(tenant.id, other.application.id);
    expect(await failureReason(auth(sign({ kid: otherKey.kid })))).toBe("unknown_assertion_key");
  });

  it("rejects an assertion for a client of another tenant", async () => {
    const { sign } = await setup();
    const otherTenant = await createTenant();
    const assertion = await sign({ tenantSlug: otherTenant.slug });
    expect(await failureReason(authenticateClientAssertion(otherTenant, assertion, IP))).toBe(
      "unknown_client",
    );
  });

  it("accepts a retiring key before retires_at and rejects it after", async () => {
    const { key, sign, auth } = await setup();
    const setRetiresAt = (ms: number) =>
      db
        .update(applicationKeys)
        .set({ status: "retiring", retiresAt: new Date(Date.now() + ms) })
        .where(eq(applicationKeys.id, key.id));
    await setRetiresAt(60_000);
    await expect(auth(sign())).resolves.toBeDefined();
    await setRetiresAt(-1000);
    expect(await failureReason(auth(sign()))).toBe("unknown_assertion_key");
  });

  it("rejects an assertion from an application registered for client secrets", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id);
    const { key, privateKey } = await createApplicationKey(tenant.id, application.id);
    const assertion = signClientAssertion(privateKey, {
      clientId: application.clientId,
      kid: key.kid,
      tenantSlug: tenant.slug,
    });
    expect(await failureReason(authenticateClientAssertion(tenant, await assertion, IP))).toBe(
      "auth_method_mismatch",
    );
  });

  it("rejects a secret from an application registered for private_key_jwt", async () => {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id, {
      tokenEndpointAuthMethod: "private_key_jwt",
    });
    const creds = { clientId: application.clientId, clientSecret, viaBasic: true };
    expect(await failureReason(authenticateClient(tenant, creds, IP))).toBe("auth_method_mismatch");
  });

  it("rejects an RS256-signed assertion and an unsigned token", async () => {
    const { application, key, auth } = await setup();
    const { privateKey } = await generateKeyPair("RS256");
    const claims = { iss: application.clientId, sub: application.clientId, jti: "x" };
    const rs = new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: key.kid })
      .setExpirationTime("1m")
      .sign(privateKey);
    expect(await failureReason(auth(rs))).toBe("bad_assertion");
    expect(await failureReason(auth("not-a-jwt"))).toBe("bad_assertion");
  });

  it("rejects a disabled application only after the assertion verified", async () => {
    const { tenant, application, sign, auth } = await setup();
    await setApplicationStatus(tenant.id, application.id, "disabled");
    expect(await failureReason(auth(sign()))).toBe("client_disabled");
  });

  it("rejects a client_id that differs from iss", async () => {
    const { application, sign, auth } = await setup();
    expect(await failureReason(auth(sign(), "other-client"))).toBe("bad_assertion");
    await expect(auth(sign(), application.clientId)).resolves.toBeDefined();
  });
});

describe("MemoryStore maxKeys (bounds the jti replay cache)", () => {
  it("evicts the oldest key and never exceeds the cap", async () => {
    const store = new MemoryStore<true>(60_000, 3);
    for (let i = 0; i < 10; i++) {
      await store.set(`k${i}`, true, 60_000);
      expect(await store.size()).toBeLessThanOrEqual(3);
    }
    expect(await store.has("k6")).toBe(false);
    expect(await store.has("k9")).toBe(true);
    await store.set("k9", true, 60_000); // overwriting an existing key evicts nothing
    expect(await store.has("k7")).toBe(true);
    store.destroy();
  });
});
