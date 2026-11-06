import { applications, db, pool, runMigrations } from "@handsal/db";
import { CLIENT_ID_REGEX } from "@handsal/shared";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../middleware/error-handler.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.app.js";
import { verifySecret } from "../utils/secrets.js";
import {
  deleteApplication,
  getApplication,
  listApplications,
  revokeAllApplicationTokens,
  rotateSecret,
  setApplicationStatus,
  updateApplication,
} from "./application.service.js";

async function rowOf(appId: string) {
  const [row] = await db.select().from(applications).where(eq(applications.id, appId));
  return row;
}

async function apiErrorOf(promise: Promise<unknown>): Promise<ApiError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ApiError);
  return err as ApiError;
}

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

describe("createApplication", () => {
  it("returns an app_ client id and an hs_ secret whose hash verifies", async () => {
    const tenant = await createTenant();
    const { application, clientSecret } = await createApplication(tenant.id, {
      name: "billing",
      tokenTtlSeconds: 900,
    });

    expect(application.clientId).toMatch(CLIENT_ID_REGEX);
    expect(clientSecret).toMatch(/^hs_[A-Za-z0-9]{48}$/);
    expect(application).toMatchObject({
      name: "billing",
      kind: "service",
      status: "active",
      tokenEndpointAuthMethod: "client_secret_basic",
      tokenTtlSeconds: 900,
    });
    expect(application).not.toHaveProperty("clientSecretHash");

    const row = await rowOf(application.id);
    expect(row.clientSecretHash).not.toContain(clientSecret);
    expect(await verifySecret(clientSecret, row.clientSecretHash ?? "")).toBe(true);
  });

  it("rejects a duplicate name in the same tenant with 409 application_exists", async () => {
    const tenant = await createTenant();
    await createApplication(tenant.id, { name: "dup" });

    const err = await apiErrorOf(createApplication(tenant.id, { name: "dup" }));
    expect(err.statusCode).toBe(409);
    expect(err.errorCode).toBe("application_exists");

    // Same name in another tenant is fine.
    const other = await createTenant();
    await expect(createApplication(other.id, { name: "dup" })).resolves.toBeDefined();
  });
});

describe("listApplications", () => {
  it("enriches rows with resourceCount and scopeNames and filters by q and status", async () => {
    const tenant = await createTenant();
    const { application: a } = await createApplication(tenant.id, { name: "alpha" });
    const { application: b } = await createApplication(tenant.id, { name: "beta" });
    const payments = await createResourceWithScopes(tenant.id, "https://pay", [
      "p:read",
      "p:write",
    ]);
    const invoices = await createResourceWithScopes(tenant.id, "https://inv", ["i:read"]);
    await grant(tenant.id, a.id, [
      payments.scopes[1].id,
      payments.scopes[0].id,
      invoices.scopes[0].id,
    ]);
    await setApplicationStatus(tenant.id, b.id, "disabled");

    // Another tenant's app must not appear.
    await createApplication((await createTenant()).id, { name: "alpha-foreign" });

    const all = await listApplications(tenant.id);
    expect(all.map((x) => x.name)).toEqual(["alpha", "beta"]);
    expect(all[0]).toMatchObject({
      resourceCount: 2,
      scopeNames: ["i:read", "p:read", "p:write"],
      lastTokenAt: null,
    });
    expect(all[1]).toMatchObject({ resourceCount: 0, scopeNames: [] });

    expect((await listApplications(tenant.id, { q: "ALP" })).map((x) => x.name)).toEqual(["alpha"]);
    expect(
      (await listApplications(tenant.id, { q: a.clientId.slice(4, 12) })).map((x) => x.id),
    ).toEqual([a.id]);
    expect((await listApplications(tenant.id, { q: "%" })).length).toBe(0);
    expect((await listApplications(tenant.id, { status: "active" })).map((x) => x.name)).toEqual([
      "alpha",
    ]);
    expect((await listApplications(tenant.id, { status: "disabled" })).map((x) => x.name)).toEqual([
      "beta",
    ]);
  });

  it("needs_attention = disabled or inside a secret-rotation grace window", async () => {
    const tenant = await createTenant();
    const { application: rotating } = await createApplication(tenant.id, { name: "rotating" });
    const { application: disabled } = await createApplication(tenant.id, { name: "disabled" });
    await createApplication(tenant.id, { name: "fine" });
    await rotateSecret(tenant.id, rotating.id, 3600);
    await setApplicationStatus(tenant.id, disabled.id, "disabled");

    const names = (await listApplications(tenant.id, { status: "needs_attention" })).map(
      (x) => x.name,
    );
    expect(names).toEqual(["disabled", "rotating"]);
  });
});

describe("get / update / delete", () => {
  it("scopes every operation to the tenant", async () => {
    const tenant = await createTenant();
    const other = await createTenant();
    const { application } = await createApplication(tenant.id, { name: "svc" });

    expect((await apiErrorOf(getApplication(other.id, application.id))).statusCode).toBe(404);
    expect(
      (await apiErrorOf(updateApplication(other.id, application.id, { name: "x" }))).statusCode,
    ).toBe(404);
    expect((await apiErrorOf(deleteApplication(other.id, application.id))).statusCode).toBe(404);
    expect((await getApplication(tenant.id, application.id)).name).toBe("svc");
  });

  it("updates fields, maps rename conflicts to 409, deletes", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id, { name: "svc" });
    await createApplication(tenant.id, { name: "taken" });

    const updated = await updateApplication(tenant.id, application.id, {
      description: "d",
      tokenEndpointAuthMethod: "client_secret_post",
      tokenTtlSeconds: null,
    });
    expect(updated).toMatchObject({
      name: "svc",
      description: "d",
      tokenEndpointAuthMethod: "client_secret_post",
      tokenTtlSeconds: null,
    });

    const err = await apiErrorOf(updateApplication(tenant.id, application.id, { name: "taken" }));
    expect(err.statusCode).toBe(409);

    await deleteApplication(tenant.id, application.id);
    expect((await apiErrorOf(getApplication(tenant.id, application.id))).statusCode).toBe(404);
  });
});

describe("rotateSecret", () => {
  it("moves the current hash to previous with an expiry and stores a new hash", async () => {
    const tenant = await createTenant();
    const { application, clientSecret: oldSecret } = await createApplication(tenant.id);
    const before = Date.now();

    const { clientSecret, previousSecretExpiresAt } = await rotateSecret(
      tenant.id,
      application.id,
      600,
    );

    const row = await rowOf(application.id);
    expect(clientSecret).not.toBe(oldSecret);
    expect(await verifySecret(clientSecret, row.clientSecretHash ?? "")).toBe(true);
    expect(await verifySecret(oldSecret, row.previousSecretHash ?? "")).toBe(true);
    expect(row.previousSecretExpiresAt?.toISOString()).toBe(previousSecretExpiresAt);
    const expiresMs = Date.parse(previousSecretExpiresAt ?? "");
    expect(expiresMs).toBeGreaterThanOrEqual(before + 600_000);
    expect(expiresMs).toBeLessThan(Date.now() + 600_000 + 1000);
    expect(row.secretRotatedAt).not.toBeNull();
  });

  it("grace 0 invalidates the previous secret immediately", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id);

    const { previousSecretExpiresAt } = await rotateSecret(tenant.id, application.id, 0);

    expect(previousSecretExpiresAt).toBeNull();
    const row = await rowOf(application.id);
    expect(row.previousSecretHash).toBeNull();
    expect(row.previousSecretExpiresAt).toBeNull();
  });
});

describe("revokeAllApplicationTokens", () => {
  it("sets tokens_not_before to now", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id);

    const updated = await revokeAllApplicationTokens(tenant.id, application.id);

    expect(updated.tokensNotBefore).not.toBeNull();
    expect(Math.abs(Date.parse(updated.tokensNotBefore ?? "") - Date.now())).toBeLessThan(5000);
  });
});
