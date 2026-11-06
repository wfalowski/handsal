import { z } from "zod";

const role = z.enum(["owner", "admin", "auditor"]);

export const memberCreateSchema = z.object({
  email: z.email().max(255),
  name: z.string().min(1).max(255).optional(),
  role,
});

export const memberUpdateSchema = z.object({ role });

export const memberDtoSchema = z.object({
  adminUserId: z.uuid(),
  email: z.string(),
  name: z.string(),
  role,
  isActive: z.boolean(),
  lastLoginAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
});

export const signingKeyDtoSchema = z.object({
  id: z.uuid(),
  kid: z.string(),
  algorithm: z.string(),
  status: z.enum(["active", "retiring", "retired"]),
  retiresAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
});
