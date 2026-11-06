import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { type HandsalClient, redact, type TokenResult } from "./handsal.js";

export const FETCH_TOOL_NAME = "handsal_fetch";

export const FETCH_TOOL_DESCRIPTION =
  "Call an HTTP API protected by Handsal. Obtains a short-lived access token for the given resource and scopes (asking a human for approval when the scope requires it) and returns only the HTTP response.";

export const fetchToolInput = {
  url: z.url().describe("Full URL to call; must be under `resource`"),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
  body: z.string().optional().describe("Request body, sent as-is"),
  content_type: z.string().optional().describe("Content-Type of body (default application/json)"),
  resource: z
    .string()
    .min(1)
    .describe("Handsal resource audience, e.g. https://api.acme.io/invoices"),
  scope: z.string().min(1).describe("Space-separated scopes"),
  task_id: z
    .string()
    .regex(/^[A-Za-z0-9._:-]{1,128}$/, "task_id must be 1 to 128 characters of A-Za-z0-9._:-")
    .describe("Identifier of the task this call belongs to (A-Za-z0-9._:-, up to 128)"),
  justification: z.string().max(500).optional().describe("Why, shown to the human approver"),
  actor_hint: z.string().max(255).optional().describe("Who the agent is acting for"),
};

export type FetchToolArgs = z.infer<z.ZodObject<typeof fetchToolInput>>;

const BODY_LIMIT_BYTES = 64 * 1024;
const MESSAGE_LIMIT = 300;
export const DEFAULT_HTTP_TIMEOUT_SECONDS = 60;

/** True when `url` is `resource` itself or a path below it, on the same scheme, host and port. */
export function isUnderResource(url: string, resource: string): boolean {
  let target: URL;
  let base: URL;
  try {
    target = new URL(url); // resolves dot segments the way fetch will
    base = new URL(resource);
  } catch {
    return false; // a non-URL audience (e.g. a urn) has no URL under it
  }
  if (target.username || target.password) return false;
  // Encoded separators and decoded `..` segments can reach outside the prefix on servers that decode.
  if (/%2f|%5c/i.test(target.pathname)) return false;
  try {
    if (target.pathname.split("/").some((segment) => decodeURIComponent(segment) === "..")) {
      return false;
    }
  } catch {
    return false; // malformed percent-encoding
  }
  if (target.protocol !== base.protocol || target.host.toLowerCase() !== base.host.toLowerCase()) {
    return false;
  }
  const basePath = base.pathname.replace(/\/+$/, "");
  return target.pathname === basePath || target.pathname.startsWith(`${basePath}/`);
}

function text(value: string, isError = false): CallToolResult {
  return { content: [{ type: "text", text: value }], ...(isError && { isError: true }) };
}

/** Reads at most `limit` bytes of the body, decoding UTF-8 without splitting a character. */
async function readLimited(res: Response, limit: number): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let out = "";
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return out + decoder.decode();
    const room = limit - bytes;
    if (value.length > room) {
      // stream: true keeps an incomplete trailing character buffered (and then dropped).
      out += decoder.decode(value.subarray(0, room), { stream: true });
      await reader.cancel();
      return `${out}\n[truncated]`;
    }
    bytes += value.length;
    out += decoder.decode(value, { stream: true });
  }
}

export function createFetchTool(deps: {
  client: Pick<HandsalClient, "getToken">;
  approvalsUrl?: string;
  fetch?: typeof fetch;
  timeoutSeconds?: number;
}): (args: FetchToolArgs) => Promise<CallToolResult> {
  const fetchFn = deps.fetch ?? fetch;
  const timeoutMs = (deps.timeoutSeconds ?? DEFAULT_HTTP_TIMEOUT_SECONDS) * 1000;

  return async (args) => {
    if (!isUnderResource(args.url, args.resource)) {
      return text(
        `url is not under resource; refusing to send a token for ${args.resource} to ${args.url}`,
        true,
      );
    }

    let token: TokenResult;
    try {
      token = await deps.client.getToken({
        resource: args.resource,
        scope: args.scope,
        taskId: args.task_id,
        actorHint: args.actor_hint,
        justification: args.justification,
      });
    } catch (err) {
      const message = redact((err as Error).message).slice(0, MESSAGE_LIMIT);
      return text(`Could not reach Handsal: ${message}`, true);
    }

    if (token.kind === "pending") {
      const where = deps.approvalsUrl ? ` at ${deps.approvalsUrl}` : "";
      return text(
        `Waiting for human approval (approval_id ${token.approvalId}). Waited ${token.waitedSeconds} s. A human must approve this request in the Handsal admin UI${where}. Call handsal_fetch again with the same arguments to keep waiting; the request will not be duplicated.`,
      );
    }
    if (token.kind === "denied") {
      const retry =
        token.retryAfterSeconds !== undefined ? ` (retry after ${token.retryAfterSeconds} s)` : "";
      return text(`Handsal refused the token: ${token.error}: ${token.description}${retry}`, true);
    }

    const headers: Record<string, string> = { authorization: `Bearer ${token.accessToken}` };
    if (args.body !== undefined) headers["content-type"] = args.content_type ?? "application/json";
    try {
      // Redirects are not followed: the token must only ever go to URLs under `resource`.
      const res = await fetchFn(args.url, {
        method: args.method,
        headers,
        body: args.body,
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
      const body = await readLimited(res, BODY_LIMIT_BYTES);
      const approved = token.viaApproval
        ? " (sent with a human-approved token, valid for this call only)"
        : "";
      const lines = [`HTTP ${res.status} ${res.statusText}${approved}`];
      for (const name of ["content-type", "location"]) {
        const value = res.headers.get(name);
        if (value) lines.push(`${name}: ${value}`);
      }
      return text(redact(`${lines.join("\n")}\n\n${body}`, [token.accessToken]));
    } catch (err) {
      return text(redact(`Request failed: ${(err as Error).message}`, [token.accessToken]), true);
    }
  };
}
