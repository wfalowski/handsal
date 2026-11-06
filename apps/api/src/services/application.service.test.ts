import { applicationKeys, applications, db, pool, runMigrations } from "@handsal/db";
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
} from "../test/factories.js";
import { verifySecret } from "../utils/crypto.js";
import {
  createApplication as createApplicationService,
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

describe("agent applications", () => {
  const guardrails = {
    agentRuntime: "langgraph",
    operatorEmail: "ops@example.com",
    allowedCidrs: ["10.40.0.0/16"],
    maxScopesPerToken: 2,
    tokenBudgetPerHour: 120,
  };

  it("kind agent persists guardrails; omitted kind is service with null/empty agent fields", async () => {
    const tenant = await createTenant();
    const agent = (await createApplication(tenant.id, { kind: "agent", ...guardrails }))
      .application;
    expect(agent).toMatchObject({ kind: "agent", ...guardrails });
    const service = (await createApplication(tenant.id)).application;
    expect(service).toMatchObject({
      kind: "service",
      agentRuntime: null,
      operatorEmail: null,
      allowedCidrs: [],
      maxScopesPerToken: null,
      tokenBudgetPerHour: null,
    });
    expect((await listApplications(tenant.id, { kind: "agent" })).map((a) => a.id)).toEqual([
      agent.id,
    ]);
  });

  it("delegation fields round-trip on agents; defaults on services; rejected on services", async () => {
    const tenant = await createTenant();
    const { application: agent } = await createApplication(tenant.id, {
      kind: "agent",
      mayActFor: ["tenant"],
      delegationScopeMode: "agent_only",
    });
    expect(agent).toMatchObject({ mayActFor: ["tenant"], delegationScopeMode: "agent_only" });
    const cleared = await updateApplication(tenant.id, agent.id, { mayActFor: [] });
    expect(cleared).toMatchObject({ mayActFor: [], delegationScopeMode: "agent_only" });

    const { application: svc } = await createApplication(tenant.id);
    expect(svc).toMatchObject({ mayActFor: [], delegationScopeMode: "intersection" });
    const err = await apiErrorOf(updateApplication(tenant.id, svc.id, { mayActFor: ["users"] }));
    expect([err.statusCode, err.errorCode]).toEqual([400, "agent_fields_on_service"]);
  });

  it("agent fields on a service → 400 agent_fields_on_service (create and patch)", async () => {
    const tenant = await createTenant();
    const created = await apiErrorOf(createApplication(tenant.id, { maxScopesPerToken: 2 }));
    expect([created.statusCode, created.errorCode]).toEqual([400, "agent_fields_on_service"]);

    const { application } = await createApplication(tenant.id);
    const patched = await apiErrorOf(
      updateApplication(tenant.id, application.id, { allowedCidrs: ["10.0.0.0/8"] }),
    );
    expect([patched.statusCode, patched.errorCode]).toEqual([400, "agent_fields_on_service"]);
  });

  it("patches guardrails; null clears them; a CIDR Node rejects → 400 invalid_cidr", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id, { kind: "agent", ...guardrails });
    const cleared = await updateApplication(tenant.id, application.id, {
      allowedCidrs: null,
      tokenBudgetPerHour: null,
      maxScopesPerToken: 5,
    });
    expect(cleared).toMatchObject({
      allowedCidrs: [],
      tokenBudgetPerHour: null,
      maxScopesPerToken: 5,
    });

    // Passes the shape regex, fails Node's parser.
    const bad = await apiErrorOf(
      updateApplication(tenant.id, application.id, { allowedCidrs: ["999.0.0.0/8"] }),
    );
    expect([bad.statusCode, bad.errorCode]).toEqual([400, "invalid_cidr"]);
  });

  it("private_key_jwt requires an active registered key → 409 no_application_key", async () => {
    const tenant = await createTenant();
    const onCreate = await apiErrorOf(
      createApplicationService(tenant.id, {
        name: "jwt-app",
        tokenEndpointAuthMethod: "private_key_jwt",
      }),
    );
    expect([onCreate.statusCode, onCreate.errorCode]).toEqual([409, "no_application_key"]);

    const { application } = await createApplication(tenant.id, { kind: "agent" });
    const toJwt = { tokenEndpointAuthMethod: "private_key_jwt" } as const;
    const key = {
      tenantId: tenant.id,
      applicationId: application.id,
      kid: "k1",
      publicKeyPem: "pem",
      fingerprintSha256: "f".repeat(64),
    };
    await db.insert(applicationKeys).values({ ...key, status: "retiring" });
    expect((await apiErrorOf(updateApplication(tenant.id, application.id, toJwt))).errorCode).toBe(
      "no_application_key",
    );
    await db
      .insert(applicationKeys)
      .values({ ...key, kid: "k2", fingerprintSha256: "e".repeat(64) });
    expect(
      (await updateApplication(tenant.id, application.id, toJwt)).tokenEndpointAuthMethod,
    ).toBe("private_key_jwt");
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
