import { applicationKeys, db, pool, runMigrations, tenants } from "@handsal/db";
import { eq } from "drizzle-orm";
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import {
  addMember,
  createAdminUser,
  createApplication,
  createTenant,
  truncateAll,
} from "../../test/factories.js";
import { jsonRequest, loginAs } from "../../test/helpers.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

async function pem(alg: "ES256" | "ES384" = "ES256") {
  const { publicKey } = await generateKeyPair(alg, { extractable: true });
  return exportSPKI(publicKey);
}

async function setup(role: "admin" | "auditor" = "admin") {
  const tenant = await createTenant();
  const { user, password } = await createAdminUser();
  await addMember(tenant.id, user.id, role);
  const { cookie, csrf } = await loginAs(app, user.email, password);
  const headers = { cookie, "x-csrf-token": csrf };
  const { application } = await createApplication(tenant.id, {
    tokenEndpointAuthMethod: "private_key_jwt",
  });
  const url = `/api/tenants/${tenant.id}/applications/${application.id}/keys`;
  const req = async (method: string, path: string, body?: unknown) => {
    const res = await jsonRequest(app, method, path, body, headers);
    const text = await res.text();
    // Key responses never carry key material.
    expect(text).not.toContain("PRIVATE");
    expect(text).not.toContain("BEGIN PUBLIC KEY");
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
  return { tenant, application, url, req };
}

describe("…/applications/:appId/keys", () => {
  it("registers, lists, retires and deletes a key", async () => {
    const { application, url, req } = await setup();
    const created = await req("POST", url, { kid: "k1", publicKeyPem: await pem() });
    expect(created.status).toBe(201);
    expect(created.body).toEqual({
      id: expect.any(String),
      applicationId: application.id,
      kid: "k1",
      algorithm: "ES256",
      fingerprintSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      status: "active",
      retiresAt: null,
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
    });

    expect((await req("GET", url)).body).toEqual({ items: [created.body] });

    // The only key of a private_key_jwt application can be neither retired nor deleted.
    for (const res of [
      await req("POST", `${url}/${created.body.id}/retire`, { graceSeconds: 60 }),
      await req("DELETE", `${url}/${created.body.id}`),
    ]) {
      expect(res.status).toBe(409);
      expect(res.body.error).toBe("no_application_key");
    }
    expect((await req("GET", url)).body).toEqual({ items: [created.body] });

    const next = await req("POST", url, { kid: "k2", publicKeyPem: await pem() });
    const retired = await req("POST", `${url}/${created.body.id}/retire`, { graceSeconds: 60 });
    expect(retired.status).toBe(200);
    expect(retired.body.status).toBe("retiring");
    expect(Date.parse(retired.body.retiresAt)).toBeGreaterThan(Date.now());

    expect((await req("DELETE", `${url}/${created.body.id}`)).status).toBe(204);
    expect((await req("DELETE", `${url}/${created.body.id}`)).status).toBe(404);
    expect((await req("GET", url)).body).toEqual({ items: [next.body] });
  });

  it("refuses to delete the last usable key, but not an expired retiring one", async () => {
    const { url, req } = await setup();
    const a = await req("POST", url, { kid: "a", publicKeyPem: await pem() });
    const b = await req("POST", url, { kid: "b", publicKeyPem: await pem() });
    // b retiring within its grace still verifies, so a's retire is refused but its delete is not.
    expect((await req("POST", `${url}/${b.body.id}/retire`, { graceSeconds: 600 })).status).toBe(
      200,
    );
    expect((await req("POST", `${url}/${a.body.id}/retire`, { graceSeconds: 600 })).status).toBe(
      409,
    );
    expect((await req("DELETE", `${url}/${a.body.id}`)).status).toBe(204);
    expect((await req("DELETE", `${url}/${b.body.id}`)).status).toBe(409);
    await db
      .update(applicationKeys)
      .set({ retiresAt: new Date(Date.now() - 1000) })
      .where(eq(applicationKeys.id, b.body.id));
    expect((await req("DELETE", `${url}/${b.body.id}`)).status).toBe(204);
  });

  it("allows removing the last key of an application using a client secret", async () => {
    const { tenant, req } = await setup();
    const { application } = await createApplication(tenant.id);
    const url = `/api/tenants/${tenant.id}/applications/${application.id}/keys`;
    const k = await req("POST", url, { kid: "k1", publicKeyPem: await pem() });
    expect((await req("POST", `${url}/${k.body.id}/retire`, { graceSeconds: 0 })).status).toBe(200);
    expect((await req("DELETE", `${url}/${k.body.id}`)).status).toBe(204);
  });

  it("rejects a P-384 key, a private key and garbage with 400 invalid_public_key", async () => {
    const { url, req } = await setup();
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    for (const publicKeyPem of [await pem("ES384"), await exportPKCS8(privateKey), "nope"]) {
      const res = await req("POST", url, { kid: "k1", publicKeyPem });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_public_key");
    }
  });

  it("rejects a duplicate kid and the same key under a new kid with 409", async () => {
    const { url, req } = await setup();
    const key = await pem();
    expect((await req("POST", url, { kid: "k1", publicKeyPem: key })).status).toBe(201);
    const dupKid = await req("POST", url, { kid: "k1", publicKeyPem: await pem() });
    expect(dupKid.status).toBe(409);
    expect(dupKid.body.error).toBe("application_key_exists");
    const dupKey = await req("POST", url, { kid: "k2", publicKeyPem: key });
    expect(dupKey.status).toBe(409);
  });

  it("an auditor can list but not write", async () => {
    const { url, req } = await setup("auditor");
    expect((await req("GET", url)).status).toBe(200);
    expect((await req("POST", url, { kid: "k1", publicKeyPem: await pem() })).status).toBe(403);
  });

  it("another tenant's application or key is 404", async () => {
    const { tenant, url, req } = await setup();
    const created = await req("POST", url, { kid: "k1", publicKeyPem: await pem() });
    const other = await createApplication((await createTenant()).id);
    const foreignUrl = `/api/tenants/${tenant.id}/applications/${other.application.id}/keys`;
    expect((await req("GET", foreignUrl)).status).toBe(404);
    expect((await req("POST", foreignUrl, { kid: "k", publicKeyPem: await pem() })).status).toBe(
      404,
    );
    expect((await req("DELETE", `${foreignUrl}/${created.body.id}`)).status).toBe(404);
    expect((await req("POST", `${url}/not-a-uuid/retire`, {})).status).toBe(404);
  });

  it("keys cascade with their application and their tenant", async () => {
    const first = await setup();
    await first.req("POST", first.url, { kid: "k1", publicKeyPem: await pem() });
    const appUrl = `/api/tenants/${first.tenant.id}/applications/${first.application.id}`;
    expect((await first.req("DELETE", appUrl)).status).toBe(204);
    expect(await db.select().from(applicationKeys)).toHaveLength(0);

    const second = await setup();
    await second.req("POST", second.url, { kid: "k1", publicKeyPem: await pem() });
    await db.delete(tenants).where(eq(tenants.id, second.tenant.id));
    expect(await db.select().from(applicationKeys)).toHaveLength(0);
  });
});
