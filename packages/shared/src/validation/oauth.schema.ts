import { z } from "zod";
import { TOKEN_TYPE_URNS } from "../constants/oauth.js";
import { TASK_ID_REGEX } from "../constants/regex.js";
import { approvalRequestExtraSchema } from "./approval.schema.js";

// Form fields are strings; the route (not the schema) decides unsupported_grant_type.
export const tokenRequestSchema = z.object({
  grant_type: z.string(),
  scope: z.string().optional(),
  resource: z.string().min(1).max(512),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
  client_assertion: z.string().max(4096).optional(),
  client_assertion_type: z.string().max(128).optional(),
  task_id: z.string().regex(TASK_ID_REGEX).optional(),
  ...approvalRequestExtraSchema.shape,
});

// Form fields of grant_type=urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693).
// actor_token / actor_token_type are out of scope: their presence fails parsing (route answers invalid_request).
export const tokenExchangeSchema = z.object({
  subject_token: z.string().min(1).max(8192),
  subject_token_type: z.enum([TOKEN_TYPE_URNS.ACCESS_TOKEN, TOKEN_TYPE_URNS.JWT]),
  resource: z.string().min(1).max(512),
  scope: z.string().optional(),
  task_id: z.string().regex(TASK_ID_REGEX).optional(),
  actor_token: z.never().optional(),
  actor_token_type: z.never().optional(),
});

export const introspectRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().optional(),
});

export const revokeRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().optional(),
});
