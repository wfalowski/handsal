import { z } from "zod";
import { DEFAULTS } from "../constants/defaults.js";

const ttl = z.number().int().min(DEFAULTS.TTL_MIN).max(DEFAULTS.TTL_MAX);
const authMethodEnum = z.enum(["client_secret_basic", "client_secret_post", "private_key_jwt"]);
const mvpAuthMethod = authMethodEnum.refine((v) => v !== "private_key_jwt", {
  message: "private_key_jwt is not available yet",
});

export const applicationCreateSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  tokenEndpointAuthMethod: mvpAuthMethod.optional(),
  tokenTtlSeconds: ttl.optional(),
});

export const applicationUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).nullable().optional(),
  tokenEndpointAuthMethod: mvpAuthMethod.optional(),
  tokenTtlSeconds: ttl.nullable().optional(),
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
});
