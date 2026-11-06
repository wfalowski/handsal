import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createApp, createReadiness } from "./app.js";
import { formRequest } from "./test/helpers.js";

const app = createApp({ readinessCheck: async () => {} });

describe("app", () => {
  it("GET /health returns 200 with status and version", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", version: expect.any(String) });
  });

  it("GET /ready returns 200 when the readiness check resolves", async () => {
    const res = await app.request("/ready");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("GET /ready returns 503 when the pool rejects", async () => {
    const down = createApp({
      readinessCheck: () => Promise.reject(new Error("connection refused")),
    });
    const res = await down.request("/ready");
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ status: "db_unavailable" });
  });

  it("GET /ready returns 503 migrating until markReady, then runs the real check", async () => {
    let realChecks = 0;
    const readiness = createReadiness(async () => {
      realChecks++;
    });
    const gated = createApp({ readinessCheck: readiness.check });

    const before = await gated.request("/ready");
    expect(before.status).toBe(503);
    expect(await before.json()).toEqual({ status: "migrating" });
    expect((await gated.request("/health")).status).toBe(200);
    expect(realChecks).toBe(0);

    readiness.markReady();
    const after = await gated.request("/ready");
    expect(after.status).toBe(200);
    expect(realChecks).toBe(1);
  });

  it("sets security headers and a strict API CSP", async () => {
    const res = await app.request("/health");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
    expect(res.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
  });

  it("assigns X-Request-Id when absent and echoes a provided one", async () => {
    expect((await app.request("/health")).headers.get("X-Request-Id")).toBeTruthy();
    const res = await app.request("/health", { headers: { "X-Request-Id": "my-id" } });
    expect(res.headers.get("X-Request-Id")).toBe("my-id");
  });

  it("returns a JSON 404 for unknown routes", async () => {
    const res = await app.request("/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found", error_description: "Not found" });
  });

  it("rejects an oversized /t/* body with 413", async () => {
    const res = await formRequest(app, "/t/acme/oauth/token", { pad: "A".repeat(20 * 1024) });
    expect(res.status).toBe(413);
  });

  it("applies CORS on /api/* for allowed origins only", async () => {
    const res = await app.request("/api/anything", {
      headers: { Origin: "http://localhost:5173" },
    });
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("http://localhost:5173");
    const health = await app.request("/health", { headers: { Origin: "http://localhost:5173" } });
    expect(health.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("serves the SPA fallback without swallowing API paths", async () => {
    const publicDir = mkdtempSync(join(tmpdir(), "handsal-spa-"));
    try {
      writeFileSync(join(publicDir, "index.html"), "<!doctype html><title>spa</title>");
      const spa = createApp({ readinessCheck: async () => {}, serveSpa: true, publicDir });

      for (const path of ["/t/acme/oauth/bogus", "/api/nope"]) {
        const res = await spa.request(path);
        // /api/* is behind admin auth, so an unknown path there is 401; /t/* is a plain 404.
        expect([401, 404], path).toContain(res.status);
        expect(res.headers.get("Content-Type"), path).toContain("application/json");
      }

      const res = await spa.request("/anything-else");
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("<title>spa</title>");
    } finally {
      rmSync(publicDir, { recursive: true, force: true });
    }
  });
});
