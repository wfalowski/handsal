import { z } from "zod";
import {
  AGENT_BUDGET_MAX,
  AGENT_BUDGET_MIN,
  AGENT_CIDRS_MAX,
  AGENT_MAX_SCOPES_MAX,
  AGENT_MAX_SCOPES_MIN,
  DEFAULTS,
} from "../constants/defaults.js";
import { CIDR_REGEX } from "../constants/regex.js";

const ttl = z.number().int().min(DEFAULTS.TTL_MIN).max(DEFAULTS.TTL_MAX);
const authMethodEnum = z.enum(["client_secret_basic", "client_secret_post", "private_key_jwt"]);

// Agent-only guardrails; the API rejects them on service applications (agent_fields_on_service).
const agentRuntime = z.string().min(1).max(64);
const operatorEmail = z.email().max(255);
const allowedCidrs = z.array(z.string().max(49).regex(CIDR_REGEX)).max(AGENT_CIDRS_MAX);
const maxScopesPerToken = z.number().int().min(AGENT_MAX_SCOPES_MIN).max(AGENT_MAX_SCOPES_MAX);
const tokenBudgetPerHour = z.number().int().min(AGENT_BUDGET_MIN).max(AGENT_BUDGET_MAX);

export const applicationCreateSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  // Absent means "service" (applied by the API); optional rather than default() so z.infer keeps it optional for callers.
  kind: z.enum(["service", "agent"]).optional(),
  tokenEndpointAuthMethod: authMethodEnum.optional(),
  tokenTtlSeconds: ttl.optional(),
  agentRuntime: agentRuntime.optional(),
  operatorEmail: operatorEmail.optional(),
  allowedCidrs: allowedCidrs.optional(),
  maxScopesPerToken: maxScopesPerToken.optional(),
  tokenBudgetPerHour: tokenBudgetPerHour.optional(),
});

// `kind` is immutable after create.
export const applicationUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).nullable().optional(),
  tokenEndpointAuthMethod: authMethodEnum.optional(),
  tokenTtlSeconds: ttl.nullable().optional(),
  agentRuntime: agentRuntime.nullable().optional(),
  operatorEmail: operatorEmail.nullable().optional(),
  allowedCidrs: allowedCidrs.nullable().optional(),
  maxScopesPerToken: maxScopesPerToken.nullable().optional(),
  tokenBudgetPerHour: tokenBudgetPerHour.nullable().optional(),
});

export const rotateSecretSchema = z.object({
  graceSeconds: z.number().int().min(0).max(604800).default(DEFAULTS.SECRET_GRACE_SECONDS),
});

export const grantsReplaceSchema = z.object({
  scopeIds: z.array(z.uuid()).max(500),
});

export const applicationDtoSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  description: z.string().nullable(),
  kind: z.enum(["service", "agent"]),
  clientId: z.string(),
  tokenEndpointAuthMethod: authMethodEnum,
  tokenTtlSeconds: z.number().int().nullable(),
  status: z.enum(["active", "disabled"]),
  secretRotatedAt: z.iso.datetime().nullable(),
  previousSecretExpiresAt: z.iso.datetime().nullable(),
  tokensNotBefore: z.iso.datetime().nullable(),
  lastTokenAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  // shortcut: agent fields are optional until the API mapper emits them (Task 6.2 slice C); then drop `.optional()`.
  agentRuntime: z.string().nullable().optional(),
  operatorEmail: z.string().nullable().optional(),
  allowedCidrs: z.array(z.string()).optional(),
  maxScopesPerToken: z.number().int().nullable().optional(),
  tokenBudgetPerHour: z.number().int().nullable().optional(),
});
