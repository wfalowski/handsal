import { z } from "zod";
import { DEFAULTS } from "../constants/defaults.js";

export const applicationKeyCreateSchema = z.object({
  kid: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9._:-]+$/),
  publicKeyPem: z.string().min(1).max(4096),
});

export const applicationKeyRetireSchema = z.object({
  graceSeconds: z.number().int().min(0).max(604800).default(DEFAULTS.SECRET_GRACE_SECONDS),
});

// Deliberately omits publicKeyPem: no key material in responses.
export const applicationKeyDtoSchema = z.object({
  id: z.uuid(),
  applicationId: z.uuid(),
  kid: z.string(),
  algorithm: z.string(),
  fingerprintSha256: z.string(),
  status: z.enum(["active", "retiring"]),
  retiresAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
