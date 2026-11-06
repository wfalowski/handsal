import { z } from "zod";
import { SCOPE_NAME_REGEX } from "../constants/defaults.js";

export const scopeCreateSchema = z.object({
  name: z.string().regex(SCOPE_NAME_REGEX),
  description: z.string().max(1000).optional(),
});

export const scopeUpdateSchema = z.object({
  name: z.string().regex(SCOPE_NAME_REGEX).optional(),
  description: z.string().max(1000).nullable().optional(),
});

export const scopeDtoSchema = z.object({
  id: z.uuid(),
  resourceId: z.uuid(),
  name: z.string(),
  description: z.string().nullable(),
  agentPolicy: z.enum(["auto", "approval", "never"]),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
