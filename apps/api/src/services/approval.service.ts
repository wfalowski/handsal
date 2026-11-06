import { adminUsers, applications, approvalRequests, approvalRules, db, scopes } from "@handsal/db";
import type { ApprovalCountsDto, ApprovalDto, approvalsQuerySchema } from "@handsal/shared";
import { DEFAULTS, OAUTH_ERRORS } from "@handsal/shared";
import { and, count, desc, eq, gt, inArray, lt, lte, type SQL, sql } from "drizzle-orm";
import type { z } from "zod";
import type { Actor } from "../middleware/admin-auth.js";
import { ApiError, OAuthError } from "../middleware/error-handler.js";
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
 * event. Returns the approval id the agent polls with and the row status. When every approval
 * scope of the request has a matching auto-approve rule the row is created already `approved`
 * (the agent still polls once); otherwise it is `pending` and the tenant webhook is notified.
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
): Promise<{ approvalId: string; status: "pending" | "approved" }> {
  const taskId = request.taskId ?? null;
  const actorHint = request.actorHint ?? null;
  const justification = request.justification ?? null;
  // An agent re-sending the original request instead of polling keeps one card in the queue.
  // shortcut: two concurrent first requests can still create two rows; harmless, a partial unique index would make it exact.
  const [existing] = await db
    .select({ id: approvalRequests.id, status: approvalRequests.status })
    .from(approvalRequests)
    .where(
      and(
        eq(approvalRequests.tenantId, tenant.id),
        eq(approvalRequests.applicationId, application.id),
        eq(approvalRequests.resourceId, request.resourceId),
        // A live pending row, or an approved one (e.g. by a rule) not yet redeemed.
        sql`(${approvalRequests.status} = 'pending' or (${approvalRequests.status} = 'approved' and ${approvalRequests.consumedAt} is null))`,
        gt(approvalRequests.expiresAt, sql`now()`),
        sql`${approvalRequests.scopes} = ${sql.param(request.scopes, approvalRequests.scopes)}`,
        sql`${approvalRequests.taskId} is not distinct from ${taskId}`,
        // The human consents to the story shown on the card: a changed story opens a new card.
        sql`${approvalRequests.actorHint} is not distinct from ${actorHint}`,
        sql`${approvalRequests.justification} is not distinct from ${justification}`,
      ),
    )
    .limit(1);
  if (existing?.status === "pending" || existing?.status === "approved") {
    return { approvalId: existing.id, status: existing.status };
  }

  const approvalScopes = await db
    .select({ id: scopes.id, name: scopes.name })
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

  // Rule-approved rows never reach the human queue, so only the human path is capped.
  if (!rule) {
    // shortcut: count and insert are not serialised, so concurrent requests can overshoot by the in-flight count.
    const [{ live }] = await db
      .select({ live: count() })
      .from(approvalRequests)
      .where(
        and(
          eq(approvalRequests.tenantId, tenant.id),
          eq(approvalRequests.applicationId, application.id),
          eq(approvalRequests.status, "pending"),
          gt(approvalRequests.expiresAt, sql`now()`),
        ),
      );
    if (live >= DEFAULTS.APPROVAL_MAX_PENDING_PER_APPLICATION) {
      const err = new OAuthError(OAUTH_ERRORS.ACCESS_DENIED, 400, "Too many pending approvals");
      err.reason = "approval_queue_full";
      throw err;
    }
  }

  const [row] = await db
    .insert(approvalRequests)
    .values({
      tenantId: tenant.id,
      applicationId: application.id,
      resourceId: request.resourceId,
      audience: request.audience,
      scopes: request.scopes,
      actorHint,
      taskId,
      justification,
      expiresAt: sql`now() + make_interval(secs => ${DEFAULTS.APPROVAL_TTL_SECONDS})`,
      ...(rule && {
        status: "approved" as const,
        decidedByRuleId: rule.id,
        decidedByLabel: `rule: ${approvalScopes.find((s) => s.id === rule.scopeId)?.name}`,
        decidedAt: sql`now()`,
      }),
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
  return { approvalId: row.id, status: rule ? "approved" : "pending" };
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
  // decided_by_label wins when set; the joins only cover rows decided before the column existed.
  if (deciderName !== null) decidedBy = { kind: "user", label: a.decidedByLabel ?? deciderName };
  else if (a.decidedByRuleId !== null)
    decidedBy = { kind: "rule", label: a.decidedByLabel ?? `rule: ${ruleScopeName}` };
  // No surviving user or rule id: the ADMIN_API_KEY actor, or a deleted user / rule whose stored
  // label still says who decided (rule labels start with "rule: "). Expiry never sets decided_at.
  else if (a.decidedAt !== null) {
    const label = a.decidedByLabel ?? "API key";
    const kind = label === "API key" ? "api-key" : label.startsWith("rule: ") ? "rule" : "user";
    decidedBy = { kind, label };
  }
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
  // Bound the scan to the union the filters need, not the tenant's whole history.
  const window = sql`((${live}) or ${decided24h})`;
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
      .where(and(eq(approvalRequests.tenantId, tenantId), window)),
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
      decidedByLabel: actor.kind === "user" ? actor.name : "API key",
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

const JOB_BATCH = 1000;

/** Mark overdue pending approvals expired (all tenants), at most 1000 per run. Returns the updated count. */
export async function expirePendingApprovals(): Promise<number> {
  const overdue = and(
    eq(approvalRequests.status, "pending"),
    lte(approvalRequests.expiresAt, sql`now()`),
  );
  const batch = db
    .select({ id: approvalRequests.id })
    .from(approvalRequests)
    .where(overdue)
    .limit(JOB_BATCH);
  const result = await db
    .update(approvalRequests)
    .set({ status: "expired" })
    // Re-checked: a row decided between the subselect and the update stays decided.
    .where(and(inArray(approvalRequests.id, batch), overdue));
  const expired = result.rowCount ?? 0;
  if (expired > 0) logger.info({ expired }, "Expired pending approvals");
  return expired;
}

/** Delete resolved approvals (all tenants) older than `retentionDays`, at most 1000 per run. */
export async function purgeResolvedApprovals(retentionDays: number): Promise<number> {
  const batch = db
    .select({ id: approvalRequests.id })
    .from(approvalRequests)
    .where(
      and(
        inArray(approvalRequests.status, ["approved", "denied", "expired"]),
        // expires_at is never before decided_at (only live rows are decided), so it covers both.
        lt(approvalRequests.expiresAt, sql`now() - make_interval(days => ${retentionDays})`),
      ),
    )
    .limit(JOB_BATCH);
  const result = await db.delete(approvalRequests).where(inArray(approvalRequests.id, batch));
  const deleted = result.rowCount ?? 0;
  if (deleted > 0) logger.info({ deleted, retentionDays }, "Purged resolved approvals");
  return deleted;
}
