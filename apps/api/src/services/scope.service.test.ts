import { applicationGrants, db, pool, runMigrations } from "@handsal/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../middleware/error-handler.js";
import {
  createApplication,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.js";
import { createScope, deleteScope, listScopes, updateScope } from "./scope.service.js";

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

async function twoResources() {
  const tenant = await createTenant();
  const pay = await createResourceWithScopes(tenant.id, "https://api.acme.io/payments", []);
  const inv = await createResourceWithScopes(tenant.id, "https://api.acme.io/invoices", []);
  return { tenant, pay: pay.resource, inv: inv.resource };
}

describe("scope CRUD", () => {
  it("create (agentPolicy defaults to auto, accepted when given), list, update, delete", async () => {
    const { tenant, pay } = await twoResources();
    const s = await createScope(tenant.id, pay.id, { name: "p:write", description: "Write" });
    expect(s).toMatchObject({
      resourceId: pay.id,
      name: "p:write",
      description: "Write",
      agentPolicy: "auto",
    });
    const t = await createScope(tenant.id, pay.id, { name: "p:read", agentPolicy: "never" });
    expect(t).toMatchObject({ description: null, agentPolicy: "never" });

    expect((await listScopes(tenant.id, pay.id)).map((x) => x.name)).toEqual(["p:read", "p:write"]);

    const u = await updateScope(tenant.id, pay.id, s.id, {
      description: null,
      agentPolicy: "approval",
    });
    expect(u).toMatchObject({ name: "p:write", description: null, agentPolicy: "approval" });
    expect(await updateScope(tenant.id, pay.id, s.id, {})).toMatchObject({ name: "p:write" });

    await deleteScope(tenant.id, pay.id, s.id);
    expect((await listScopes(tenant.id, pay.id)).map((x) => x.name)).toEqual(["p:read"]);
  });

  it("duplicate name within a resource → 409 scope_exists; same name on another resource OK", async () => {
    const { tenant, pay, inv } = await twoResources();
    await createScope(tenant.id, pay.id, { name: "read" });
    const err = await apiErrorOf(createScope(tenant.id, pay.id, { name: "read" }));
    expect([err.statusCode, err.errorCode]).toEqual([409, "scope_exists"]);
    await expect(createScope(tenant.id, inv.id, { name: "read" })).resolves.toMatchObject({
      name: "read",
    });

    const other = await createScope(tenant.id, pay.id, { name: "write" });
    const rename = await apiErrorOf(updateScope(tenant.id, pay.id, other.id, { name: "read" }));
    expect(rename.errorCode).toBe("scope_exists");
  });

  it("deleting a scope removes its grants", async () => {
    const tenant = await createTenant();
    const { resource, scopes } = await createResourceWithScopes(tenant.id, "urn:acme:x", ["a"]);
    const { application } = await createApplication(tenant.id);
    await grant(tenant.id, application.id, [scopes[0].id]);
    await deleteScope(tenant.id, resource.id, scopes[0].id);
    expect(await db.select().from(applicationGrants)).toEqual([]);
  });
});

describe("404s", () => {
  it("unknown / foreign resource → resource_not_found", async () => {
    const a = await createTenant();
    const { pay } = await twoResources();
    for (const resourceId of [pay.id, "nope", crypto.randomUUID()]) {
      expect((await apiErrorOf(listScopes(a.id, resourceId))).errorCode).toBe("resource_not_found");
      expect((await apiErrorOf(createScope(a.id, resourceId, { name: "x" }))).errorCode).toBe(
        "resource_not_found",
      );
    }
  });

  it("scope of another resource / bad id → scope_not_found", async () => {
    const { tenant, pay, inv } = await twoResources();
    const s = await createScope(tenant.id, pay.id, { name: "read" });
    for (const scopeId of [s.id, "nope"]) {
      expect(
        (await apiErrorOf(updateScope(tenant.id, inv.id, scopeId, { name: "y" }))).errorCode,
      ).toBe("scope_not_found");
      expect((await apiErrorOf(deleteScope(tenant.id, inv.id, scopeId))).errorCode).toBe(
        "scope_not_found",
      );
    }
  });
});
