import { runMigrations } from "@handsal/db";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../app.js";
import { ensureActiveKey } from "../../services/signing-key.service.js";
import { createTenant, truncateAll } from "../../test/factories.js";

const app = createApp({ readinessCheck: async () => {} });

beforeAll(async () => {
  await runMigrations();
});
beforeEach(async () => {
  await truncateAll();
});

const get = (slug: string) => app.request(`/t/${slug}/.well-known/jwks.json`);

describe("jwks", () => {
  it("returns public ES256 keys only, with cache header", async () => {
    const t = await createTenant();
    const key = await ensureActiveKey(t.id);
    const res = await get(t.slug);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    const { keys } = await res.json();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatchObject({ kty: "EC", crv: "P-256", kid: key.kid });
    expect(keys[0]).not.toHaveProperty("d");
  });

  it("creates a key for a tenant that has none yet", async () => {
    const t = await createTenant();
    const { keys } = await (await get(t.slug)).json();
    expect(keys).toHaveLength(1);
  });

  it("serves a paused tenant", async () => {
    const t = await createTenant({ status: "paused" });
    const res = await get(t.slug);
    expect(res.status).toBe(200);
    expect((await res.json()).keys.length).toBeGreaterThan(0);
  });

  it("404 JSON for unknown slug", async () => {
    const res = await get("nope");
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
  });
});
