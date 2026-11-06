#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { HandsalClient } from "./handsal.js";
import {
  createFetchTool,
  FETCH_TOOL_DESCRIPTION,
  FETCH_TOOL_NAME,
  fetchToolInput,
} from "./tool.js";

const envSchema = z.object({
  HANDSAL_TOKEN_ENDPOINT: z.url(),
  HANDSAL_CLIENT_ID: z.string().min(1),
  HANDSAL_KID: z.string().min(1),
  HANDSAL_PRIVATE_KEY_FILE: z.string().min(1),
  HANDSAL_APPROVAL_WAIT_SECONDS: z.coerce.number().int().min(0).max(3600).default(90),
  HANDSAL_APPROVALS_URL: z.url().optional(),
});

function fail(message: string): never {
  console.error(`handsal-mcp-agent: ${message}`);
  process.exit(1);
}

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  const issues = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`);
  fail(`invalid configuration\n${issues.join("\n")}`);
}
const env = parsed.data;

let privateKeyPem: string;
try {
  privateKeyPem = readFileSync(env.HANDSAL_PRIVATE_KEY_FILE, "utf8");
} catch (err) {
  fail(
    `HANDSAL_PRIVATE_KEY_FILE: cannot read ${env.HANDSAL_PRIVATE_KEY_FILE} (${(err as NodeJS.ErrnoException).code ?? "error"})`,
  );
}

let client: HandsalClient;
try {
  client = new HandsalClient({
    tokenEndpoint: env.HANDSAL_TOKEN_ENDPOINT,
    clientId: env.HANDSAL_CLIENT_ID,
    kid: env.HANDSAL_KID,
    privateKeyPem,
    approvalWaitSeconds: env.HANDSAL_APPROVAL_WAIT_SECONDS,
  });
} catch (err) {
  fail(`HANDSAL_PRIVATE_KEY_FILE: ${(err as Error).message}`);
}

const server = new McpServer({ name: "handsal-agent", version: "0.0.1" });
server.registerTool(
  FETCH_TOOL_NAME,
  { description: FETCH_TOOL_DESCRIPTION, inputSchema: fetchToolInput },
  createFetchTool({ client, approvalsUrl: env.HANDSAL_APPROVALS_URL }),
);
await server.connect(new StdioServerTransport());
