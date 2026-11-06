import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { HandsalClient } from "./handsal.js";

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
  task_id: z.string().min(1).max(128).describe("Identifier of the task this call belongs to"),
  justification: z.string().max(500).optional().describe("Why, shown to the human approver"),
  actor_hint: z.string().max(255).optional().describe("Who the agent is acting for"),
};

export type FetchToolArgs = z.infer<z.ZodObject<typeof fetchToolInput>>;

const BODY_LIMIT_BYTES = 64 * 1024;

function normalize(value: string): string {
  let normalized = value;
  try {
    normalized = new URL(value).href; // resolves dot segments the way fetch will
  } catch {
    // not a URL (e.g. a urn audience): compare as given
  }
  return normalized.replace(/\/+$/, "");
}

function isUnderResource(url: string, resource: string): boolean {
  const base = normalize(resource);
  const target = normalize(url);
  return (
    target === base ||
    target.startsWith(`${base}/`) ||
    target.startsWith(`${base}?`) ||
    target.startsWith(`${base}#`)
  );
}

function text(value: string, isError = false): CallToolResult {
  return { content: [{ type: "text", text: value }], ...(isError && { isError: true }) };
}

/** Removes the bearer token (and any authorization header line) from text shown to the model. */
function redact(value: string, accessToken: string): string {
  return value
    .split(accessToken)
    .join("[redacted]")
    .replace(/authorization:\s*bearer\s+\S+/gi, "authorization: [redacted]");
}

export function createFetchTool(deps: {
  client: Pick<HandsalClient, "getToken">;
  approvalsUrl?: string;
  fetch?: typeof fetch;
}): (args: FetchToolArgs) => Promise<CallToolResult> {
  const fetchFn = deps.fetch ?? fetch;

  return async (args) => {
    if (!isUnderResource(args.url, args.resource)) {
      return text(
        `url is not under resource; refusing to send a token for ${args.resource} to ${args.url}`,
        true,
      );
    }

    let token: Awaited<ReturnType<HandsalClient["getToken"]>>;
    try {
      token = await deps.client.getToken({
        resource: args.resource,
        scope: args.scope,
        taskId: args.task_id,
        actorHint: args.actor_hint,
        justification: args.justification,
      });
    } catch (err) {
      return text(`Could not reach Handsal: ${(err as Error).message}`, true);
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
      });
      // shortcut: the whole body is buffered before truncation; stream it if APIs return huge bodies.
      const raw = Buffer.from(await res.arrayBuffer());
      const body =
        raw.length > BODY_LIMIT_BYTES
          ? `${raw.subarray(0, BODY_LIMIT_BYTES).toString("utf8")}\n[truncated]`
          : raw.toString("utf8");
      const lines = [`HTTP ${res.status} ${res.statusText}`];
      for (const name of ["content-type", "location"]) {
        const value = res.headers.get(name);
        if (value) lines.push(`${name}: ${value}`);
      }
      return text(redact(`${lines.join("\n")}\n\n${body}`, token.accessToken));
    } catch (err) {
      return text(redact(`Request failed: ${(err as Error).message}`, token.accessToken), true);
    }
  };
}
