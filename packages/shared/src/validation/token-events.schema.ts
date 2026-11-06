import { z } from "zod";
import { DEFAULTS } from "../constants/defaults.js";

export const tokenEventsQuerySchema = z.object({
  outcome: z.enum(["issued", "denied", "revoked"]).optional(),
  applicationId: z.uuid().optional(),
  q: z.string().max(255).optional(),
  since: z.iso.datetime().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(DEFAULTS.TOKEN_EVENTS_PAGE_SIZE),
  cursor: z.string().optional(),
});

export const tokenEventDtoSchema = z.object({
  id: z.string(),
  applicationId: z.uuid().nullable(),
  applicationClientId: z.string().nullable(),
  resourceId: z.uuid().nullable(),
  audience: z.string().nullable(),
  outcome: z.enum(["issued", "denied", "revoked"]),
  reason: z.string().nullable(),
  scopes: z.array(z.string()),
  jti: z.string().nullable(),
  expiresAt: z.iso.datetime().nullable(),
  sourceIp: z.string().nullable(),
  createdAt: z.iso.datetime(),
});

const count = z.number().int().min(0);
export const tokenStatsDtoSchema = z.object({
  issued24h: count,
  issuedPrev24h: count,
  denied24h: count,
  requests24h: count,
  activeApps24h: count,
  totalApps: count,
});
