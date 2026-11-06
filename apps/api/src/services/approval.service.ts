import { adminUsers, applications, approvalRequests, approvalRules, db, scopes } from "@handsal/db";
import type { ApprovalCountsDto, ApprovalDto, approvalsQuerySchema } from "@handsal/shared";
import { DEFAULTS } from "@handsal/shared";
import { and, desc, eq, gt, inArray, lte, type SQL, sql } from "drizzle-orm";
import type { z } from "zod";
import type { Actor } from "../middleware/admin-auth.js";
import { ApiError } from "../middleware/error-handler.js";
import { createLogger } from "../utils/logger.js";
import { countApprovalRules, findMatchingRule } from "./approval-rule.service.js";
import { notifyApprovalPending } from "./approval-webhook.service.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import type { Tenant } from "./tenant.service.js";
import { recordTokenEvent } from "./token-event.service.js";

const logger = createLogger("approval-service");

export type ApprovalsQuery = z.output<typeof approvalsQuerySchema>;
export type ApprovalRow = typeof approvalRequests.$inferSelect;

/**
 * Open (or reuse) a pending approval for an agent token request and record a `pending` token
 * event. Returns the approval id the agent polls with. When every approval scope of the request
 * has a matching auto-approve rule the row is created already `approved` (the agent still polls
 * once); otherwise it is `pending` and the tenant webhook is notified.
 */
export async function createApprovalRequest(
  tenant: Tenant,
  application: AuthenticatedApplication,
  request: {
    resourceId: string;
    audience: string;
    scopes: string[];
    actorHint?: string;
    taskId?: string;
    justification?: string;
  },
  ctx: { sourceIp: string },
): Promise<string> {
  const taskId = request.taskId ?? null;
  // An agent re-sending the original request instead of polling keeps one card in the queue.
  // shortcut: two concurrent first requests can still create two rows; harmless, a partial unique index would make it exact.
  const [existing] = await db
    .select({ id: approvalRequests.id })
    .from(approvalRequests)
    .where(
      and(
        eq(approvalRequests.tenantId, tenant.id),
        eq(approvalRequests.applicationId, application.id),
        eq(approvalRequests.resourceId, request.resourceId),
        eq(approvalRequests.status, "pending"),
        gt(approvalRequests.expiresAt, sql`now()`),
        sql`${approvalRequests.scopes} = ${sql.param(request.scopes, approvalRequests.scopes)}`,
        sql`${approvalRequests.taskId} is not distinct from ${taskId}`,
      ),
    )
    .limit(1);
  if (existing) return existing.id;

  const approvalScopes = await db
    .select({ id: scopes.id })
    .from(scopes)
    .where(
      and(
        eq(scopes.tenantId, tenant.id),
        eq(scopes.resourceId, request.resourceId),
        inArray(scopes.name, request.scopes),
        eq(scopes.agentPolicy, "approval"),
      ),
    );
  const rule = await findMatchingRule(
    tenant.id,
    approvalScopes.map((s) => s.id),
    { applicationId: application.id, taskId, scopeCount: request.scopes.length },
  );

  const [row] = await db
    .insert(approvalRequests)
    .values({
      tenantId: tenant.id,
      applicationId: application.id,
      resourceId: request.resourceId,
      audience: request.audience,
      scopes: request.scopes,
      actorHint: request.actorHint ?? null,
      taskId,
      justification: request.justification ?? null,
      expiresAt: sql`now() + make_interval(secs => ${DEFAULTS.APPROVAL_TTL_SECONDS})`,
      ...(rule && { status: "approved" as const, decidedByRuleId: rule.id, decidedAt: sql`now()` }),
    })
    .returning();

  await recordTokenEvent({
    tenantId: tenant.id,
    applicationId: application.id,
    applicationClientId: application.clientId,
    resourceId: request.resourceId,
    audience: request.audience,
    outcome: "pending",
    scopes: request.scopes,
    sourceIp: ctx.sourceIp.slice(0, 45),
    taskId,
  });
  if (!rule) {
    // Fire-and-forget after the insert committed: a slow or failing webhook never touches the token request.
    void notifyApprovalPending(
      tenant,
      toDto({
        approval: row,
        applicationName: application.name,
        clientId: application.clientId,
        deciderName: null,
        ruleScopeName: null,
      }),
    );
  }
  return row.id;
}

/**
 * Atomically mark an approved, unexpired, unconsumed approval as consumed. Returns the row when
 * this caller won, otherwise the current row (or null) so the caller can map the state.
 */
export async function claimApproval(
  tenantId: string,
  applicationId: string,
  approvalId: string,
): Promise<{ claimed: ApprovalRow | null; current: ApprovalRow | null }> {
  const scope = and(
    eq(approvalRequests.id, approvalId),
    eq(approvalRequests.tenantId, tenantId),
    eq(approvalRequests.applicationId, applicationId),
  );
  // One statement: two concurrent polls cannot both see consumed_at IS NULL.
  const [claimed] = await db
    .update(approvalRequests)
    .set({ consumedAt: sql`now()` })
    .where(
      and(
        scope,
        eq(approvalRequests.status, "approved"),
        sql`${approvalRequests.consumedAt} is null`,
        gt(approvalRequests.expiresAt, sql`now()`),
      ),
    )
    .returning();
  if (claimed) return { claimed, current: claimed };
  const [current] = await db.select().from(approvalRequests).where(scope);
  return { claimed: null, current: current ?? null };
}

// Microsecond-precision text for the keyset (see token-event.service.ts).
const createdAtText = sql<string>`to_char(${approvalRequests.createdAt} at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function encodeCursor(createdAt: string, id: string): string {
  return Buffer.from(`${createdAt}|${id}`).toString("base64url");
}

function decodeCursor(cursor: string): { createdAt: string; id: string } {
  const [createdAt, id] = Buffer.from(cursor, "base64url").toString("utf8").split("|");
  if (!createdAt || Number.isNaN(Date.parse(createdAt)) || !id || !UUID_RE.test(id)) {
    throw new ApiError(400, "invalid_cursor", "Invalid cursor");
  }
  return { createdAt, id };
}

const dtoColumns = {
  approval: approvalRequests,
  applicationName: applications.name,
  clientId: applications.clientId,
  deciderName: adminUsers.name,
  ruleScopeName: scopes.name,
};

type DtoRow = {
  approval: ApprovalRow;
  applicationName: string;
  clientId: string;
  deciderName: string | null;
  ruleScopeName: string | null;
};

function toDto({
  approval: a,
  applicationName,
  clientId,
  deciderName,
  ruleScopeName,
}: DtoRow): ApprovalDto {
  let decidedBy: ApprovalDto["decidedBy"] = null;
  if (deciderName !== null) decidedBy = { kind: "user", label: deciderName };
  else if (a.decidedByRuleId !== null)
    decidedBy = { kind: "rule", label: `rule: ${ruleScopeName}` };
  // shortcut: a deleted rule nulls decided_by_rule_id, so its rows then read as "API key"; keep a rule label column if that matters.
  // A decision with no user is the ADMIN_API_KEY actor (expiry never sets decided_at).
  else if (a.decidedAt !== null) decidedBy = { kind: "api-key", label: "API key" };
  return {
    id: a.id,
    applicationId: a.applicationId,
    applicationName,
    clientId,
    audience: a.audience,
    scopes: a.scopes,
    actorHint: a.actorHint,
    taskId: a.taskId,
    justification: a.justification,
    status: a.status,
    expiresAt: a.expiresAt.toISOString(),
    createdAt: a.createdAt.toISOString(),
    decidedAt: a.decidedAt?.toISOString() ?? null,
    decidedBy,
  };
}

function selectDtos() {
  return db
    .select({ ...dtoColumns, createdAtText })
    .from(approvalRequests)
    .innerJoin(
      applications,
      and(
        eq(applications.tenantId, approvalRequests.tenantId),
        eq(applications.id, approvalRequests.applicationId),
      ),
    )
    .leftJoin(adminUsers, eq(adminUsers.id, approvalRequests.decidedBy))
    .leftJoin(
      approvalRules,
      and(
        eq(approvalRules.tenantId, approvalRequests.tenantId),
        eq(approvalRules.id, approvalRequests.decidedByRuleId),
      ),
    )
    .leftJoin(
      scopes,
      and(eq(scopes.tenantId, approvalRules.tenantId), eq(scopes.id, approvalRules.scopeId)),
    );
}

/** Queue counters; "today" is the trailing 24 h, like the Tokens page. */
export async function getApprovalCounts(tenantId: string): Promise<ApprovalCountsDto> {
  const live = sql`${approvalRequests.status} = 'pending' and ${approvalRequests.expiresAt} > now()`;
  const decided24h = sql`${approvalRequests.decidedAt} >= now() - interval '24 hours'`;
  const [[row], rules] = await Promise.all([
    db
      .select({
        pending: sql<number>`count(*) filter (where ${live})`.mapWith(Number),
        oldestPendingAt: sql<
          string | null
        >`min(${approvalRequests.createdAt}) filter (where ${live})`,
        approvedToday:
          sql<number>`count(*) filter (where ${approvalRequests.status} = 'approved' and ${decided24h})`.mapWith(
            Number,
          ),
        deniedToday:
          sql<number>`count(*) filter (where ${approvalRequests.status} = 'denied' and ${decided24h})`.mapWith(
            Number,
          ),
        medianWaitSeconds: sql<
          number | null
        >`percentile_cont(0.5) within group (order by extract(epoch from (${approvalRequests.decidedAt} - ${approvalRequests.createdAt}))) filter (where ${decided24h})`,
      })
      .from(approvalRequests)
      .where(eq(approvalRequests.tenantId, tenantId)),
    countApprovalRules(tenantId),
  ]);
  return {
    pending: row.pending,
    oldestPendingAt: row.oldestPendingAt ? new Date(row.oldestPendingAt).toISOString() : null,
    approvedToday: row.approvedToday,
    deniedToday: row.deniedToday,
    medianWaitSeconds: row.medianWaitSeconds === null ? null : Number(row.medianWaitSeconds),
    rules,
  };
}

/** Newest first, keyset-paginated on `(created_at desc, id desc)`, with the queue counters. */
export async function listApprovals(
  tenantId: string,
  query: ApprovalsQuery,
): Promise<{ items: ApprovalDto[]; nextCursor: string | null; counts: ApprovalCountsDto }> {
  const conditions: SQL[] = [eq(approvalRequests.tenantId, tenantId)];
  if (query.status === "pending") {
    // Hide dead cards between expiry-job runs.
    conditions.push(
      eq(approvalRequests.status, "pending"),
      gt(approvalRequests.expiresAt, sql`now()`),
    );
  } else {
    conditions.push(inArray(approvalRequests.status, ["approved", "denied", "expired"]));
  }
  if (query.cursor) {
    const c = decodeCursor(query.cursor);
    conditions.push(
      sql`(${approvalRequests.createdAt}, ${approvalRequests.id}) < (${c.createdAt}::timestamptz, ${c.id}::uuid)`,
    );
  }

  const [rows, counts] = await Promise.all([
    selectDtos()
      .where(and(...conditions))
      .orderBy(desc(approvalRequests.createdAt), desc(approvalRequests.id))
      .limit(query.limit + 1),
    getApprovalCounts(tenantId),
  ]);
  const page = rows.slice(0, query.limit);
  const last = page.at(-1);
  return {
    items: page.map(toDto),
    nextCursor:
      rows.length > query.limit && last ? encodeCursor(last.createdAtText, last.approval.id) : null,
    counts,
  };
}

/** Approve or deny a live pending approval. 404 when not in this tenant, 409 when no longer pending. */
export async function decideApproval(
  tenantId: string,
  approvalId: string,
  decision: "approved" | "denied",
  actor: Actor,
): Promise<ApprovalDto> {
  const notFound = new ApiError(404, "approval_not_found", "Approval not found");
  if (!UUID_RE.test(approvalId)) throw notFound;
  const scope = and(eq(approvalRequests.id, approvalId), eq(approvalRequests.tenantId, tenantId));

  const [updated] = await db
    .update(approvalRequests)
    .set({
      status: decision,
      decidedBy: actor.kind === "user" ? actor.userId : null,
      decidedAt: sql`now()`,
    })
    .where(
      and(
        scope,
        eq(approvalRequests.status, "pending"),
        gt(approvalRequests.expiresAt, sql`now()`),
      ),
    )
    .returning({ id: approvalRequests.id });

  const [row] = await selectDtos().where(scope);
  if (!row) throw notFound;
  if (!updated) {
    const expired =
      row.approval.status === "expired" ||
      (row.approval.status === "pending" && row.approval.expiresAt <= new Date());
    throw expired
      ? new ApiError(409, "approval_expired", "Approval has expired")
      : new ApiError(409, "approval_already_decided", "Approval was already decided");
  }
  return toDto(row);
}

/** Mark overdue pending approvals expired (all tenants). Returns the updated count. */
export async function expirePendingApprovals(): Promise<number> {
  const result = await db
    .update(approvalRequests)
    .set({ status: "expired" })
    .where(
      and(eq(approvalRequests.status, "pending"), lte(approvalRequests.expiresAt, sql`now()`)),
    );
  const expired = result.rowCount ?? 0;
  if (expired > 0) logger.info({ expired }, "Expired pending approvals");
  return expired;
}
