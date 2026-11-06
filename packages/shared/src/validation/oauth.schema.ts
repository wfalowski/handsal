import { z } from "zod";
import { TASK_ID_REGEX } from "../constants/regex.js";

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
});

export const introspectRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().optional(),
});

export const revokeRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().optional(),
});
