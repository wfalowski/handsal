import { z } from "zod";
import { DEFAULTS } from "../constants/defaults.js";

const ttl = z.number().int().min(DEFAULTS.TTL_MIN).max(DEFAULTS.TTL_MAX);
const kind = z.enum(["api", "mcp"]);
const audience = z
  .string()
  .min(1)
  .max(512)
  .refine((v) => z.url().safeParse(v).success || /^urn:[a-z0-9][a-z0-9-]*:\S+$/i.test(v), {
    message: "audience must be a URL or URN",
  });

export const resourceCreateSchema = z.object({
  name: z.string().min(1).max(255),
  kind: kind.optional(),
  audience,
  tokenTtlSeconds: ttl.optional(),
});

export const resourceUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  kind: kind.optional(),
  audience: audience.optional(),
  tokenTtlSeconds: ttl.nullable().optional(),
});

export const resourceDtoSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  kind,
  audience: z.string(),
  tokenTtlSeconds: z.number().int().nullable(),
  status: z.enum(["active", "disabled"]),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
