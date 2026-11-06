import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

const { mockLogSecurityEvent } = vi.hoisted(() => ({ mockLogSecurityEvent: vi.fn() }));
vi.mock("../utils/security-logger.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../utils/security-logger.js")>()),
  logSecurityEvent: mockLogSecurityEvent,
}));

import { ApiError, errorHandler, OAuthError } from "./error-handler.js";

const app = new Hono();
app.get("/oauth", () => {
  throw new OAuthError("invalid_request", 400, "resource is required");
});
app.get("/oauth-client", () => {
  throw new OAuthError("invalid_client", 401, "Bad creds");
});
app.get("/oauth-scope", () => {
  throw new OAuthError("invalid_scope", 400, "Unknown scope");
});
app.get("/oauth-client-logged", () => {
  const err = new OAuthError("invalid_client", 401, "Bad creds");
  err.securityLogged = true;
  throw err;
});
app.get("/api", () => {
  throw new ApiError(409, "conflict", "Slug taken", { field: "slug" });
});
app.get("/zod", (c) => c.json(z.object({ name: z.string() }).parse({})));
app.get("/http", () => {
  throw new HTTPException(418, { message: "teapot" });
});
app.get("/boom", () => {
  throw new Error("boom");
});
app.onError(errorHandler);

describe("errorHandler", () => {
  it("maps OAuthError to an RFC 6749 body with no-store headers", async () => {
    const res = await app.request("/oauth");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "invalid_request",
      error_description: "resource is required",
    });
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Pragma")).toBe("no-cache");
  });

  it("sets WWW-Authenticate on 401 invalid_client", async () => {
    const res = await app.request("/oauth-client");
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="handsal"');
  });

  it("logs invalid_client / invalid_scope as their specific security events", async () => {
    await app.request("/oauth-client");
    expect(mockLogSecurityEvent).toHaveBeenLastCalledWith(
      expect.objectContaining({ event: "client_auth_failure" }),
    );
    await app.request("/oauth-scope");
    expect(mockLogSecurityEvent).toHaveBeenLastCalledWith(
      expect.objectContaining({ event: "invalid_scope_request" }),
    );
  });

  it("does not re-log an error already logged at its source", async () => {
    await app.request("/oauth-client-logged");
    expect(mockLogSecurityEvent).not.toHaveBeenCalled();
  });

  it("maps ApiError to the management envelope", async () => {
    const res = await app.request("/api");
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({
      error: "conflict",
      error_description: "Slug taken",
      details: { field: "slug" },
    });
  });

  it("maps ZodError to 400 validation_error with flattened details", async () => {
    const res = await app.request("/zod");
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("validation_error");
    expect(body.details.fieldErrors.name).toBeDefined();
  });

  it("passes HTTPException responses through", async () => {
    const res = await app.request("/http");
    expect(res.status).toBe(418);
    expect(await res.text()).toBe("teapot");
  });

  it("maps unknown errors to 500 server_error without leaking the message", async () => {
    const res = await app.request("/boom");
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({
      error: "server_error",
      error_description: "An unexpected error occurred",
    });
  });
});
