import { z } from "zod";
import { DEFAULTS, SLUG_REGEX } from "../constants/defaults.js";

export const tenantCreateSchema = z.object({
  name: z.string().min(1).max(255),
  slug: z.string().regex(SLUG_REGEX),
});

export const tenantUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  defaultTokenTtlSeconds: z.number().int().min(DEFAULTS.TTL_MIN).max(DEFAULTS.TTL_MAX).optional(),
  introspectionEnabled: z.boolean().optional(),
  keyRotationDays: z.number().int().min(1).max(3650).nullable().optional(),
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
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
