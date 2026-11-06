import { z } from "zod";

// All keys ANDed; `{}` matches every request for the rule's scope.
export const approvalConditionSchema = z
  .object({
    application_ids: z.array(z.uuid()).max(50).optional(),
    task_id_prefix: z.string().min(1).max(128).optional(),
    max_scopes: z.number().int().min(1).max(50).optional(),
  })
  .strict();

export const approvalRuleCreateSchema = z.object({
  scopeId: z.uuid(),
  condition: approvalConditionSchema.default({}),
});

export const approvalRuleDtoSchema = z.object({
  id: z.uuid(),
  scopeId: z.uuid(),
  scopeName: z.string(),
  resourceName: z.string(),
  condition: approvalConditionSchema,
  action: z.literal("auto_approve"),
  createdBy: z.string().nullable(),
  createdAt: z.iso.datetime(),
});
