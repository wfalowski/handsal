// Integration test: real Postgres. HTTP-level cases live in routes/oauth/introspect.test.ts.
import { runMigrations } from "@handsal/db";
import { SignJWT } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createTenant, truncateAll } from "../test/factories.js";
import { introspectToken, verifyTenantToken } from "./introspection.service.js";
import { ensureActiveKey } from "./signing-key.service.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("introspectToken", () => {
  it("never throws on malformed input", async () => {
    const tenant = await createTenant();
    await ensureActiveKey(tenant.id);
    for (const token of ["", "a.b.c", "x".repeat(5000), "eyJhbGciOiJub25lIn0.e30."]) {
      expect(await introspectToken(tenant, token)).toEqual({ active: false });
    }
  });

  it("rejects an HS256 token (alg confusion)", async () => {
    const tenant = await createTenant();
    await ensureActiveKey(tenant.id);
    const hs = await new SignJWT({ client_id: "app_x" })
      .setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
      .setIssuer(`https://test.example.com/t/${tenant.slug}`)
      .sign(new TextEncoder().encode("secret"));
    expect(await verifyTenantToken(tenant, hs)).toBeNull();
  });
});
