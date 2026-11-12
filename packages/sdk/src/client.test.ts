import { afterEach, describe, expect, it, type Mock, vi } from "vitest";
import { createHandsalClient, HandsalClientError, type HandsalClientOptions } from "./client.js";

const ISSUER = "https://auth.example.com/t/acme";
const RESOURCE = "https://api.acme.example/orders";

function tokenResponse(status: number, body: unknown, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function requestInit(fetchImpl: Mock<typeof fetch>, call = 0): RequestInit {
  const init = fetchImpl.mock.calls[call]?.[1];
  if (!init) throw new Error(`missing fetch call ${call}`);
  return init;
}

function decodeBasic(header: string): { clientId: string; clientSecret: string } {
  const decoded = atob(header.replace(/^Basic /i, ""));
  const colon = decoded.indexOf(":");
  const decode = (value: string) => decodeURIComponent(value.replaceAll("+", " "));
  return {
    clientId: decode(decoded.slice(0, colon)),
    clientSecret: decode(decoded.slice(colon + 1)),
  };
}

function client(fetchImpl: typeof fetch, over: Partial<HandsalClientOptions> = {}) {
  return createHandsalClient({
    issuer: `${ISSUER}/`,
    clientId: "app_test",
    clientSecret: "hs/a+b= c",
    resource: RESOURCE,
    scope: ["orders:read", "orders:write"],
    fetch: fetchImpl,
    ...over,
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("createHandsalClient", () => {
  it("requires issuer, client id, secret, and resource", () => {
    const base = { issuer: ISSUER, clientId: "app_test", clientSecret: "hs", resource: RESOURCE };
    expect(() => createHandsalClient({ ...base, issuer: " " })).toThrow(/issuer/);
    expect(() => createHandsalClient({ ...base, clientId: "" })).toThrow(/clientId/);
    expect(() => createHandsalClient({ ...base, clientSecret: " " })).toThrow(/clientSecret/);
    expect(() => createHandsalClient({ ...base, resource: "" })).toThrow(/resource/);
    expect(() =>
      createHandsalClient({ ...base, resource: `https://a.example/${"x".repeat(500)}` }),
    ).toThrow(/resource/);
    expect(() => createHandsalClient({ ...base, taskId: "has space" })).toThrow(/taskId/);
  });

  it("sends Basic client credentials and caches one token per client", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      tokenResponse(200, {
        access_token: "jwt-1",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "orders:read",
      }),
    );
    const orders = client(fetchImpl);
    const first = await orders.getToken();
    const second = await orders.authorization();
    expect(second).toBe("Bearer jwt-1");
    expect(first).toMatchObject({
      accessToken: "jwt-1",
      scope: "orders:read",
      tokenType: "Bearer",
    });
    expect(first.expiresAt).toBe(Date.now() + 3_600_000);
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const url = fetchImpl.mock.calls[0]?.[0];
    const init = requestInit(fetchImpl);
    expect(url).toBe(`${ISSUER}/oauth/token`);
    expect(init.redirect).toBe("error");
    const headers = init.headers as Record<string, string>;
    expect(decodeBasic(headers.Authorization)).toEqual({
      clientId: "app_test",
      clientSecret: "hs/a+b= c",
    });
    expect(String(init.body)).toBe(
      "grant_type=client_credentials&resource=https%3A%2F%2Fapi.acme.example%2Forders&scope=orders%3Aread+orders%3Awrite",
    );
    expect(String(init.body)).not.toContain("client_secret");

    vi.setSystemTime(Date.now() + 3_569_000);
    await orders.getToken();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + 1_000);
    fetchImpl.mockResolvedValueOnce(
      tokenResponse(200, {
        access_token: "jwt-2",
        token_type: "bearer",
        expires_in: 60,
        scope: "orders:read",
      }),
    );
    await expect(orders.getToken()).resolves.toMatchObject({ accessToken: "jwt-2" });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("shares one in-flight request and posts the secret when asked", async () => {
    let release: (response: Response) => void = () => {};
    const fetchImpl = vi.fn<typeof fetch>(
      () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    );
    const orders = client(fetchImpl, { authentication: "client_secret_post", scope: "  " });
    const first = orders.getToken();
    const second = orders.authorization();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    release(
      tokenResponse(200, {
        access_token: "jwt-1",
        token_type: "Bearer",
        expires_in: 60,
        scope: "orders:read orders:write",
      }),
    );
    await expect(first).resolves.toMatchObject({ accessToken: "jwt-1" });
    await expect(second).resolves.toBe("Bearer jwt-1");
    const init = requestInit(fetchImpl);
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
    expect(String(init.body)).toContain("client_id=app_test");
    expect(String(init.body)).toContain("client_secret=hs%2Fa%2Bb%3D+c");
    expect(String(init.body)).not.toContain("scope=");
  });

  it("does not cache an OAuth error and keeps approval and retry fields", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        tokenResponse(400, {
          error: "authorization_pending",
          error_description: "Waiting for human approval of one or more requested scopes",
          approval_id: "6b0d8c3e-1f4a-4e2b-9c7d-0a1b2c3d4e5f",
          interval: 5,
        }),
      )
      .mockResolvedValueOnce(
        tokenResponse(429, { error: "too_many_requests" }, { "Retry-After": "12" }),
      );
    const orders = client(fetchImpl, {
      taskId: "run-1",
      actorHint: "billing",
      justification: "nightly close",
    });
    await expect(orders.getToken()).rejects.toMatchObject({
      name: "HandsalClientError",
      status: 400,
      code: "authorization_pending",
      approvalId: "6b0d8c3e-1f4a-4e2b-9c7d-0a1b2c3d4e5f",
      interval: 5,
    });
    await expect(orders.getToken()).rejects.toMatchObject({ status: 429, retryAfter: 12 });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    const body = String(requestInit(fetchImpl).body);
    expect(body).toContain("task_id=run-1");
    expect(body).toContain("actor_hint=billing");
    expect(body).toContain("justification=nightly+close");
  });

  it("rejects a success body that is not a bearer token and clear() forces a new request", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(tokenResponse(200, { access_token: "jwt-1" }))
      .mockImplementation(() =>
        Promise.resolve(
          tokenResponse(200, {
            access_token: "jwt-2",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "orders:read",
          }),
        ),
      );
    const orders = client(fetchImpl);
    await expect(orders.getToken()).rejects.toBeInstanceOf(HandsalClientError);
    const token = await orders.getToken();
    expect(token.accessToken).toBe("jwt-2");
    orders.clear();
    await expect(orders.getToken()).resolves.toMatchObject({ accessToken: "jwt-2" });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });
});
