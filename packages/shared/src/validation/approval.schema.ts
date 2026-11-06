import { z } from "zod";
import { DEFAULTS } from "../constants/defaults.js";

// Form fields of the approval poll (grant_type=urn:handsal:params:grant-type:approval).
export const approvalGrantSchema = z.object({ approval_id: z.uuid() });

// Optional form params on the first token request that may go pending.
export const approvalRequestExtraSchema = z.object({
  actor_hint: z.string().max(255).optional(),
  justification: z.string().max(2000).optional(),
});

export const approvalsQuerySchema = z.object({
  status: z.enum(["pending", "resolved"]).default("pending"),
  cursor: z.string().max(256).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(DEFAULTS.APPROVALS_PAGE_SIZE),
});

export const approvalDtoSchema = z.object({
  id: z.uuid(),
  applicationId: z.uuid(),
  applicationName: z.string(),
  clientId: z.string(),
  audience: z.string(),
  scopes: z.array(z.string()),
  actorHint: z.string().nullable(),
  taskId: z.string().nullable(),
  justification: z.string().nullable(),
  status: z.enum(["pending", "approved", "denied", "expired"]),
  expiresAt: z.iso.datetime(),
  createdAt: z.iso.datetime(),
  decidedAt: z.iso.datetime().nullable(),
  decidedBy: z.object({ kind: z.enum(["user", "rule", "api-key"]), label: z.string() }).nullable(),
});

const count = z.number().int().min(0);
export const approvalCountsDtoSchema = z.object({
  pending: count,
  oldestPendingAt: z.iso.datetime().nullable(),
  approvedToday: count,
  deniedToday: count,
  medianWaitSeconds: z.number().nullable(),
  rules: count,
});
