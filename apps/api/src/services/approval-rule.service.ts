import { approvalRules, db, resources, scopes } from "@handsal/db";
import type { ApprovalCondition, ApprovalRuleDto, approvalRuleCreateSchema } from "@handsal/shared";
import { and, asc, count, eq, inArray, sql } from "drizzle-orm";
import type { z } from "zod";
import type { Actor } from "../middleware/admin-auth.js";
import { ApiError } from "../middleware/error-handler.js";

export type ApprovalRule = typeof approvalRules.$inferSelect;
export type ApprovalRuleCreateInput = z.output<typeof approvalRuleCreateSchema>;
export type RuleCandidate = { applicationId: string; taskId: string | null; scopeCount: number };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** All keys ANDed; `{}` matches every candidate. The jsonb condition is trusted as written by the validated API (not re-parsed on read); junk values fail closed. */
export function conditionMatches(condition: ApprovalCondition, candidate: RuleCandidate): boolean {
  if (condition.application_ids && !condition.application_ids.includes(candidate.applicationId))
    return false;
  if (condition.task_id_prefix && !candidate.taskId?.startsWith(condition.task_id_prefix))
    return false;
  if (condition.max_scopes !== undefined && candidate.scopeCount > condition.max_scopes)
    return false;
  return true;
}

/**
 * The first matching rule (by `created_at`) when EVERY approval scope of the request has at least
 * one matching rule; otherwise null. A rule on one scope never approves another scope.
 * Evaluated only when a request row is created: a pending row from before a rule existed keeps
 * waiting for a human (accepted).
 */
export async function findMatchingRule(
  tenantId: string,
  approvalScopeIds: string[],
  candidate: RuleCandidate,
): Promise<ApprovalRule | null> {
  if (approvalScopeIds.length === 0) return null;
  const rules = await db
    .select()
    .from(approvalRules)
    .where(
      and(eq(approvalRules.tenantId, tenantId), inArray(approvalRules.scopeId, approvalScopeIds)),
    )
    .orderBy(asc(approvalRules.createdAt), asc(approvalRules.id));
  const matching = rules.filter((r) => conditionMatches(r.condition, candidate));
  const covered = new Set(matching.map((r) => r.scopeId));
  return approvalScopeIds.every((id) => covered.has(id)) ? matching[0] : null;
}

function selectRuleDtos() {
  return db
    .select({ rule: approvalRules, scopeName: scopes.name, resourceName: resources.name })
    .from(approvalRules)
    .innerJoin(
      scopes,
      and(eq(scopes.tenantId, approvalRules.tenantId), eq(scopes.id, approvalRules.scopeId)),
    )
    .innerJoin(
      resources,
      and(eq(resources.tenantId, scopes.tenantId), eq(resources.id, scopes.resourceId)),
    );
}

function toRuleDto(r: {
  rule: ApprovalRule;
  scopeName: string;
  resourceName: string;
}): ApprovalRuleDto {
  return {
    id: r.rule.id,
    scopeId: r.rule.scopeId,
    scopeName: r.scopeName,
    resourceName: r.resourceName,
    condition: r.rule.condition,
    action: r.rule.action,
    createdBy: r.rule.createdBy,
    createdAt: r.rule.createdAt.toISOString(),
  };
}

export async function listApprovalRules(tenantId: string): Promise<ApprovalRuleDto[]> {
  const rows = await selectRuleDtos()
    .where(eq(approvalRules.tenantId, tenantId))
    .orderBy(asc(approvalRules.createdAt), asc(approvalRules.id));
  return rows.map(toRuleDto);
}

export async function countApprovalRules(tenantId: string): Promise<number> {
  const [row] = await db
    .select({ n: count() })
    .from(approvalRules)
    .where(eq(approvalRules.tenantId, tenantId));
  return row.n;
}

/**
 * 400 `invalid_rule_condition` for a `task_id_prefix`-only condition, `invalid_scope_ids` when the
 * scope is not in this tenant, `scope_not_approval` unless its policy is `approval`; 409 on a
 * duplicate `(scope, condition)`.
 */
export async function createApprovalRule(
  tenantId: string,
  input: ApprovalRuleCreateInput,
  actor: Actor,
): Promise<ApprovalRuleDto> {
  const keys = Object.keys(input.condition);
  if (keys.length === 1 && keys[0] === "task_id_prefix") {
    throw new ApiError(
      400,
      "invalid_rule_condition",
      "task_id is asserted by the agent; combine task_id_prefix with application_ids",
    );
  }
  const [scope] = await db
    .select({ id: scopes.id, agentPolicy: scopes.agentPolicy })
    .from(scopes)
    .where(and(eq(scopes.tenantId, tenantId), eq(scopes.id, input.scopeId)))
    .limit(1);
  if (!scope) {
    throw new ApiError(400, "invalid_scope_ids", "Some scope ids do not exist in this tenant", {
      unknown: [input.scopeId],
    });
  }
  // A rule on an auto/never scope would sit dormant and silently fire once the policy is tightened.
  if (scope.agentPolicy !== "approval") {
    throw new ApiError(
      400,
      "scope_not_approval",
      "Rules apply only to scopes with agent_policy=approval",
    );
  }
  // jsonb equality ignores key order. shortcut: check-then-insert can race into a duplicate; harmless (both rules match identically), a unique index on (tenant_id, scope_id, condition) would make it exact.
  const [dup] = await db
    .select({ id: approvalRules.id })
    .from(approvalRules)
    .where(
      and(
        eq(approvalRules.tenantId, tenantId),
        eq(approvalRules.scopeId, input.scopeId),
        sql`${approvalRules.condition} = ${JSON.stringify(input.condition)}::jsonb`,
      ),
    )
    .limit(1);
  if (dup) {
    throw new ApiError(409, "approval_rule_exists", "An identical rule exists for this scope");
  }
  const [created] = await db
    .insert(approvalRules)
    .values({
      tenantId,
      scopeId: input.scopeId,
      condition: input.condition,
      createdBy: actor.kind === "user" ? actor.userId : null,
    })
    .returning({ id: approvalRules.id });
  const [row] = await selectRuleDtos().where(
    and(eq(approvalRules.tenantId, tenantId), eq(approvalRules.id, created.id)),
  );
  return toRuleDto(row);
}

export async function deleteApprovalRule(tenantId: string, ruleId: string): Promise<void> {
  const notFound = new ApiError(404, "approval_rule_not_found", "Approval rule not found");
  if (!UUID_RE.test(ruleId)) throw notFound;
  const [deleted] = await db
    .delete(approvalRules)
    .where(and(eq(approvalRules.tenantId, tenantId), eq(approvalRules.id, ruleId)))
    .returning({ id: approvalRules.id });
  if (!deleted) throw notFound;
}
