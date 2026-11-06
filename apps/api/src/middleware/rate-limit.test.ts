import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import type { AppEnv } from "../app.js";
import { MemoryStore } from "../utils/store.js";
import { clientIdKey, type RateLimitEntry, rateLimit } from "./rate-limit.js";

function limitedApp(opts: Parameters<typeof rateLimit>[0]) {
  const app = new Hono<AppEnv>();
  app.use("/*", rateLimit(opts));
  app.get("/x", (c) => c.json({ ok: true }));
  return app;
}

const basic = (id: string) => `Basic ${Buffer.from(`${id}:secret`).toString("base64")}`;

describe("rateLimit", () => {
  it("allows max requests, then returns 429 with Retry-After", async () => {
    const app = limitedApp({ keyFn: () => "k", max: 3, windowMs: 60_000 });
    for (let i = 0; i < 3; i++) {
      const res = await app.request("/x");
      expect(res.status).toBe(200);
      expect(res.headers.get("X-RateLimit-Limit")).toBe("3");
      expect(res.headers.get("X-RateLimit-Remaining")).toBe(String(2 - i));
    }
    const res = await app.request("/x");
    expect(res.status).toBe(429);
    expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(0);
    expect(res.headers.get("X-RateLimit-Remaining")).toBe("0");
    expect(await res.json()).toEqual({
      error: "rate_limited",
      error_description: "Rate limit exceeded",
    });
  });

  it("uses the OAuth body and no-store headers when errorBody is oauth", async () => {
    const app = limitedApp({ keyFn: () => "k", max: 1, windowMs: 60_000, errorBody: "oauth" });
    await app.request("/x");
    const res = await app.request("/x");
    expect(res.status).toBe(429);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect((await res.json()).error).toBe("too_many_requests");
  });

  it("keeps distinct keys in independent buckets", async () => {
    const app = limitedApp({ keyFn: (c) => c.req.header("x-k") ?? "", max: 1, windowMs: 60_000 });
    expect((await app.request("/x", { headers: { "x-k": "A" } })).status).toBe(200);
    expect((await app.request("/x", { headers: { "x-k": "A" } })).status).toBe(429);
    expect((await app.request("/x", { headers: { "x-k": "B" } })).status).toBe(200);
  });

  it("starts a fresh window once the previous one expires", async () => {
    const app = limitedApp({ keyFn: () => "k", max: 1, windowMs: 20 });
    expect((await app.request("/x")).status).toBe(200);
    expect((await app.request("/x")).status).toBe(429);
    await new Promise((r) => setTimeout(r, 40));
    expect((await app.request("/x")).status).toBe(200);
  });

  it("admits a new key when maxKeys buckets are live, evicting the oldest", async () => {
    const store = new MemoryStore<RateLimitEntry>();
    let n = 0;
    const app = limitedApp({
      keyFn: () => `k${n++}`,
      max: 10,
      windowMs: 60_000,
      maxKeys: 2,
      store,
    });
    expect((await app.request("/x")).status).toBe(200);
    expect((await app.request("/x")).status).toBe(200);
    expect((await app.request("/x")).status).toBe(200);
    expect(await store.size()).toBeLessThanOrEqual(2);
    expect(await store.has("k0")).toBe(false);
    expect(await store.has("k2")).toBe(true);
    store.destroy();
  });

  it("derives Retry-After from the remaining window and sets X-RateLimit-* on 429", async () => {
    const app = limitedApp({ keyFn: () => "k", max: 1, windowMs: 5_000, errorBody: "oauth" });
    await app.request("/x");
    const res = await app.request("/x");
    expect(res.status).toBe(429);
    const retryAfter = Number(res.headers.get("Retry-After"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(5);
    expect(res.headers.get("X-RateLimit-Limit")).toBe("1");
    expect(res.headers.get("X-RateLimit-Remaining")).toBe("0");
  });
});

describe("clientIdKey", () => {
  const app = new Hono<AppEnv>();
  app.get("/k", (c) => c.text(clientIdKey(c)));
  app.post("/k", (c) => {
    c.set("formBody", { client_id: "app_from_body" });
    return c.text(clientIdKey(c));
  });

  it("keys on the Basic client_id plus the source IP", async () => {
    const res = await app.request("/k", { headers: { Authorization: basic("app_abc") } });
    expect(await res.text()).toBe("client:app_abc|ip:unknown");
  });

  it("reads client_id from the cached form body", async () => {
    const res = await app.request("/k", { method: "POST" });
    expect(await res.text()).toBe("client:app_from_body|ip:unknown");
  });

  it("falls back to the IP-only key", async () => {
    expect(await (await app.request("/k")).text()).toBe("ip:unknown");
  });
});
