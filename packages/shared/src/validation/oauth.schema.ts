import { z } from "zod";

// Form fields are strings; the route (not the schema) decides unsupported_grant_type.
export const tokenRequestSchema = z.object({
  grant_type: z.string(),
  scope: z.string().optional(),
  resource: z.string().min(1).max(512),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
});

export const introspectRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().optional(),
});

export const revokeRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().optional(),
});
