import { z } from "zod";
import { DEFAULTS } from "../constants/defaults.js";
import { SLUG_REGEX } from "../constants/regex.js";

// Trusted external IdP whose JWTs may be token-exchange subjects; one per tenant.
export const externalIdpSchema = z.object({
  issuer: z.url(),
  jwksUri: z.url({ protocol: /^https$/ }),
  audience: z.string().min(1).max(512),
});

export const tenantCreateSchema = z.object({
  name: z.string().min(1).max(255),
  slug: z.string().regex(SLUG_REGEX),
});

export const tenantUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  defaultTokenTtlSeconds: z.number().int().min(DEFAULTS.TTL_MIN).max(DEFAULTS.TTL_MAX).optional(),
  introspectionEnabled: z.boolean().optional(),
  keyRotationDays: z.number().int().min(1).max(3650).nullable().optional(),
  externalIdp: externalIdpSchema.nullable().optional(),
  // Approval webhook (6.5). https-only in production is enforced by the API route (needs env).
  approvalWebhookUrl: z.url().max(2048).nullable().optional(),
  approvalWebhookSecret: z.string().min(16).max(255).nullable().optional(),
});

export const tenantDtoSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  slug: z.string(),
  status: z.enum(["active", "paused"]),
  defaultTokenTtlSeconds: z.number().int(),
  introspectionEnabled: z.boolean(),
  keyRotationDays: z.number().int().nullable(),
  tokensNotBefore: z.iso.datetime().nullable(),
  issuer: z.string(),
  externalIdp: externalIdpSchema.nullable(),
  // The secret itself is write-only and never in the DTO.
  approvalWebhookUrl: z.string().nullable(),
  approvalWebhookSecretSet: z.boolean(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
