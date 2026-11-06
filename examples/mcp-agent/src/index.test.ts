import { describe, expect, it, vi } from "vitest";
import { createFetchTool, type FetchToolArgs } from "./tool.js";

const TOKEN = "eyJhbGciOiJFUzI1NiJ9.secret-token-value.sig";

const args: FetchToolArgs = {
  url: "https://api.acme.io/invoices/42",
  method: "GET",
  resource: "https://api.acme.io/invoices",
  scope: "invoices:read",
  task_id: "task-1",
};

function setup() {
  const getToken = vi.fn(async () => ({
    kind: "token" as const,
    accessToken: TOKEN,
    expiresAt: Date.now() + 300_000,
  }));
  // An API that echoes the Authorization header back must not leak the token to the model.
  const fetchFn = vi.fn(
    async (_url: string | URL | Request, init?: RequestInit) =>
      new Response(
        JSON.stringify({
          id: 42,
          echo: (init?.headers as Record<string, string> | undefined)?.authorization,
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      ),
  );
  const tool = createFetchTool({ client: { getToken }, fetch: fetchFn as typeof fetch });
  return { tool, getToken, fetchFn };
}

describe("handsal_fetch", () => {
  it("refuses urls outside the resource without requesting a token", async () => {
    const { tool, getToken, fetchFn } = setup();
    for (const url of [
      "https://evil.example/invoices",
      "https://api.acme.io/invoices-admin",
      "https://api.acme.io/invoices/../admin",
    ]) {
      const result = await tool({ ...args, url });
      expect(result.isError).toBe(true);
      expect(result.content[0]).toMatchObject({
        text: expect.stringContaining("url is not under resource"),
      });
    }
    expect(getToken).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("returns the HTTP response without the token", async () => {
    const { tool, fetchFn } = setup();
    const result = await tool(args);
    const text = JSON.stringify(result);
    expect(result.isError).toBeUndefined();
    expect(text).toContain("HTTP 200");
    expect(text).toContain('\\"id\\":42');
    expect(text).not.toContain("secret-token-value");
    expect(fetchFn.mock.calls[0]?.[1]?.headers).toMatchObject({ authorization: `Bearer ${TOKEN}` });
  });
});
