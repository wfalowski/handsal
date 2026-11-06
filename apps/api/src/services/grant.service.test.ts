import { pool, runMigrations } from "@handsal/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../middleware/error-handler.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  truncateAll,
} from "../test/factories.app.js";
import { getGrantedScopesForAudience, getGrants, replaceGrants } from "./grant.service.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

async function setup() {
  const tenant = await createTenant();
  const { application } = await createApplication(tenant.id);
  const payments = await createResourceWithScopes(
    tenant.id,
    "https://api.example/payments",
    ["payments:write", "payments:read"],
    { name: "Payments" },
  );
  const invoices = await createResourceWithScopes(
    tenant.id,
    "https://api.example/invoices",
    ["invoices:read"],
    { name: "Invoices" },
  );
  return { tenant, application, payments, invoices };
}

describe("replaceGrants / getGrants", () => {
  it("replaces the set and groups by resource name then scope name", async () => {
    const { tenant, application, payments, invoices } = await setup();
    const [pWrite, pRead] = payments.scopes;

    await replaceGrants(tenant.id, application.id, [pWrite.id, invoices.scopes[0].id]);
    const grants = await replaceGrants(tenant.id, application.id, [
      pWrite.id,
      pRead.id,
      invoices.scopes[0].id,
      pRead.id, // duplicates are ignored
    ]);

    expect(grants).toEqual([
      {
        resource: {
          id: invoices.resource.id,
          name: "Invoices",
          audience: "https://api.example/invoices",
          kind: "api",
        },
        scopes: [{ id: invoices.scopes[0].id, name: "invoices:read" }],
      },
      {
        resource: {
          id: payments.resource.id,
          name: "Payments",
          audience: "https://api.example/payments",
          kind: "api",
        },
        scopes: [
          { id: pRead.id, name: "payments:read" },
          { id: pWrite.id, name: "payments:write" },
        ],
      },
    ]);
    expect(await getGrants(tenant.id, application.id)).toEqual(grants);

    expect(await replaceGrants(tenant.id, application.id, [])).toEqual([]);
  });

  it("rejects foreign-tenant scope ids and leaves existing grants untouched", async () => {
    const { tenant, application, payments } = await setup();
    const foreignTenant = await createTenant();
    const foreign = await createResourceWithScopes(foreignTenant.id, "https://foreign", ["x:read"]);
    await replaceGrants(tenant.id, application.id, [payments.scopes[0].id]);
    const before = await getGrants(tenant.id, application.id);

    const err = await replaceGrants(tenant.id, application.id, [
      payments.scopes[1].id,
      foreign.scopes[0].id,
    ]).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({
      statusCode: 400,
      errorCode: "invalid_scope_ids",
      details: { unknown: [foreign.scopes[0].id] },
    });
    expect(await getGrants(tenant.id, application.id)).toEqual(before);
  });

  it("404s for an application of another tenant", async () => {
    const { application } = await setup();
    const other = await createTenant();
    await expect(replaceGrants(other.id, application.id, [])).rejects.toMatchObject({
      statusCode: 404,
    });
    expect(await getGrants(other.id, application.id)).toEqual([]);
  });
});

describe("getGrantedScopesForAudience", () => {
  it("returns the resource and granted scope names on that audience only", async () => {
    const { tenant, application, payments, invoices } = await setup();
    await replaceGrants(tenant.id, application.id, [
      payments.scopes[0].id,
      payments.scopes[1].id,
      invoices.scopes[0].id,
    ]);

    expect(
      await getGrantedScopesForAudience(tenant.id, application.id, "https://api.example/payments"),
    ).toEqual({
      resource: {
        id: payments.resource.id,
        name: "Payments",
        audience: "https://api.example/payments",
        kind: "api",
        status: "active",
        tokenTtlSeconds: null,
      },
      scopeNames: ["payments:read", "payments:write"],
    });
  });

  it("returns null for an ungranted, unknown or foreign-tenant audience", async () => {
    const { tenant, application, payments } = await setup();
    await replaceGrants(tenant.id, application.id, [payments.scopes[0].id]);
    const foreignTenant = await createTenant();
    await createResourceWithScopes(foreignTenant.id, "https://foreign", ["x:read"]);

    for (const audience of ["https://api.example/invoices", "https://nope", "https://foreign"]) {
      expect(await getGrantedScopesForAudience(tenant.id, application.id, audience)).toBeNull();
    }
    expect(
      await getGrantedScopesForAudience(
        foreignTenant.id,
        application.id,
        "https://api.example/payments",
      ),
    ).toBeNull();
  });
});
