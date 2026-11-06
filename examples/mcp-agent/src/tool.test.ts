import { describe, expect, it, vi } from "vitest";
import type { TokenResult } from "./handsal.js";
import { createFetchTool, type FetchToolArgs, fetchToolInput, isUnderResource } from "./tool.js";

const TOKEN = "eyJhbGciOiJFUzI1NiJ9.secret-token-value.sig";

const args: FetchToolArgs = {
  url: "https://api.acme.io/invoices/42",
  method: "GET",
  resource: "https://api.acme.io/invoices",
  scope: "invoices:read",
  task_id: "task-1",
};

function setup(
  respond?: () => Response,
  token: TokenResult = {
    kind: "token",
    accessToken: TOKEN,
    expiresAt: Date.now() + 300_000,
    viaApproval: false,
  },
) {
  const getToken = vi.fn(async () => token);
  // An API that echoes the Authorization header back must not leak the token to the model.
  const fetchFn = vi.fn(
    async (_url: string | URL | Request, init?: RequestInit) =>
      respond?.() ??
      new Response(
        JSON.stringify({
          id: 42,
          echo: (init?.headers as Record<string, string> | undefined)?.authorization,
        }),
        { status: 200, statusText: "OK", headers: { "content-type": "application/json" } },
      ),
  );
  const tool = createFetchTool({ client: { getToken }, fetch: fetchFn as typeof fetch });
  return { tool, getToken, fetchFn };
}

function resultText(result: Awaited<ReturnType<ReturnType<typeof createFetchTool>>>): string {
  const first = result.content[0];
  return first?.type === "text" ? first.text : "";
}

describe("isUnderResource", () => {
  it.each([
    "https://evil.example/invoices",
    "https://api.acme.io/invoices-admin",
    "https://api.acme.io/invoices/../admin",
    "https://api.acme.io/invoices/..%2fadmin",
    "https://api.acme.io/invoices/%2E%2E%2Fadmin",
    "https://api.acme.io/invoices/a%5c..%5cadmin",
    "https://user@api.acme.io/invoices/1",
    "http://api.acme.io/invoices/1",
    "https://api.acme.io:8443/invoices/1",
  ])("refuses %s", (url) => {
    expect(isUnderResource(url, "https://api.acme.io/invoices")).toBe(false);
  });

  it.each([
    "https://api.acme.io/invoices",
    "https://api.acme.io/invoices/42?expand=lines",
    "https://API.Acme.io:443/invoices/42",
  ])("allows %s", (url) => {
    expect(isUnderResource(url, "https://api.acme.io/invoices/")).toBe(true);
  });
});

describe("handsal_fetch", () => {
  it("refuses urls outside the resource without requesting a token", async () => {
    const { tool, getToken, fetchFn } = setup();
    const result = await tool({ ...args, url: "https://api.acme.io/invoices-admin" });
    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("url is not under resource");
    expect(getToken).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("returns the HTTP response without the token", async () => {
    const { tool, fetchFn } = setup();
    const result = await tool(args);
    const text = resultText(result);
    expect(result.isError).toBeUndefined();
    expect(text).toMatch(/^HTTP 200 OK\ncontent-type: application\/json\n\n/);
    expect(text).toContain('"id":42');
    expect(JSON.stringify(result)).not.toContain("secret-token-value");
    expect(fetchFn.mock.calls[0]?.[1]?.headers).toMatchObject({ authorization: `Bearer ${TOKEN}` });
  });

  it("says when a call used a human-approved token", async () => {
    const { tool } = setup(undefined, {
      kind: "token",
      accessToken: TOKEN,
      expiresAt: Date.now() + 300_000,
      viaApproval: true,
    });
    expect(resultText(await tool(args))).toMatch(/^HTTP 200 OK \(sent with a human-approved token/);
  });

  it("truncates long bodies at 64 KiB without splitting a UTF-8 character", async () => {
    // "é" is 2 bytes; an odd prefix makes byte 65536 fall in the middle of one.
    const big = `a${"é".repeat(40_000)}`;
    const { tool } = setup(() => new Response(big, { status: 200 }));
    const text = resultText(await tool(args));
    expect(text.endsWith("\n[truncated]")).toBe(true);
    expect(text).not.toContain("�");
    const body = text.slice(text.indexOf("\n\n") + 2, -"\n[truncated]".length);
    expect(Buffer.byteLength(body)).toBe(64 * 1024 - 1);
  });

  it("validates task_id format", () => {
    expect(fetchToolInput.task_id.safeParse("refund-4411:a.b_c").success).toBe(true);
    expect(fetchToolInput.task_id.safeParse("refund 4411").success).toBe(false);
    expect(fetchToolInput.task_id.safeParse("x".repeat(129)).success).toBe(false);
  });
});
