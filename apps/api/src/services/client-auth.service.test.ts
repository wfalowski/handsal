import { applications, db, pool, runMigrations } from "@handsal/db";
import { OAUTH_ERRORS } from "@handsal/shared";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { OAuthError } from "../middleware/error-handler.js";
import { createApplication, createTenant, truncateAll } from "../test/factories.app.js";
import { rotateSecret, setApplicationStatus } from "./application.service.js";
import { authenticateClient } from "./client-auth.service.js";

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
