import { applications, db, tokenEvents } from "@handsal/db";
import type { TokenEventDto, TokenStatsDto, tokenEventsQuerySchema } from "@handsal/shared";
import { and, count, desc, eq, gte, ilike, lt, or, type SQL, sql } from "drizzle-orm";
import type { z } from "zod";
import { ApiError } from "../middleware/error-handler.js";
import { createLogger } from "../utils/logger.js";

const logger = createLogger("token-event-service");

export type TokenEventInput = Omit<typeof tokenEvents.$inferInsert, "id" | "createdAt">;
export type TokenEventsQuery = z.output<typeof tokenEventsQuerySchema>;

/** Insert one token event. Never throws: a failure is logged so the token request is unaffected. */
export async function recordTokenEvent(event: TokenEventInput): Promise<void> {
  try {
    await db.insert(tokenEvents).values(event);
  } catch (err) {
    logger.error(
      { err, tenantId: event.tenantId, outcome: event.outcome },
      "Failed to record token event",
    );
  }
}

// Microsecond-precision ISO string: `Date#toISOString` truncates to ms, which would make the
// keyset skip rows sharing a millisecond.
const createdAtText = sql<string>`to_char(${tokenEvents.createdAt} at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

function encodeCursor(createdAt: string, id: number): string {
  return Buffer.from(`${createdAt}|${id}`).toString("base64url");
}

function decodeCursor(cursor: string): { createdAt: string; id: number } {
  const [createdAt, id] = Buffer.from(cursor, "base64url").toString("utf8").split("|");
  const n = Number(id);
  if (!createdAt || Number.isNaN(Date.parse(createdAt)) || !Number.isSafeInteger(n)) {
    throw new ApiError(400, "invalid_cursor", "Invalid cursor");
  }
  return { createdAt, id: n };
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

/** Newest first, keyset-paginated on `(created_at desc, id desc)`. */
export async function listTokenEvents(
  tenantId: string,
  query: TokenEventsQuery,
): Promise<{ items: TokenEventDto[]; nextCursor: string | null }> {
  const conditions: (SQL | undefined)[] = [eq(tokenEvents.tenantId, tenantId)];
  if (query.outcome) conditions.push(eq(tokenEvents.outcome, query.outcome));
  if (query.applicationId) conditions.push(eq(tokenEvents.applicationId, query.applicationId));
  if (query.since) conditions.push(gte(tokenEvents.createdAt, new Date(query.since)));
  if (query.q) {
    const q = escapeLike(query.q);
    conditions.push(
      or(
        ilike(tokenEvents.applicationClientId, `%${q}%`),
        ilike(tokenEvents.jti, `${q}%`),
        ilike(applications.name, `%${q}%`),
      ),
    );
  }
  if (query.cursor) {
    const c = decodeCursor(query.cursor);
    conditions.push(
      sql`(${tokenEvents.createdAt}, ${tokenEvents.id}) < (${c.createdAt}::timestamptz, ${c.id})`,
    );
  }

  const rows = await db
    .select({ event: tokenEvents, createdAtText })
    .from(tokenEvents)
    .leftJoin(
      applications,
      and(
        eq(applications.tenantId, tokenEvents.tenantId),
        eq(applications.id, tokenEvents.applicationId),
      ),
    )
    .where(and(...conditions))
    .orderBy(desc(tokenEvents.createdAt), desc(tokenEvents.id))
    .limit(query.limit + 1);

  const page = rows.slice(0, query.limit);
  const last = page.at(-1);
  return {
    items: page.map(({ event: e }) => ({
      id: String(e.id),
      applicationId: e.applicationId,
      applicationClientId: e.applicationClientId,
      resourceId: e.resourceId,
      audience: e.audience,
      outcome: e.outcome,
      reason: e.reason,
      scopes: e.scopes,
      jti: e.jti,
      expiresAt: e.expiresAt?.toISOString() ?? null,
      sourceIp: e.sourceIp,
      createdAt: e.createdAt.toISOString(),
    })),
    nextCursor:
      rows.length > query.limit && last ? encodeCursor(last.createdAtText, last.event.id) : null,
  };
}

/** Dashboard counters for the last 24 h (and the 24 h before, for the trend). */
export async function getTokenStats(tenantId: string): Promise<TokenStatsDto> {
  const last24h = sql`${tokenEvents.createdAt} >= now() - interval '24 hours'`;
  const issued = eq(tokenEvents.outcome, "issued");
  const [[events], [apps]] = await Promise.all([
    db
      .select({
        issued24h: sql<number>`count(*) filter (where ${issued} and ${last24h})`.mapWith(Number),
        issuedPrev24h:
          sql<number>`count(*) filter (where ${issued} and ${tokenEvents.createdAt} < now() - interval '24 hours')`.mapWith(
            Number,
          ),
        denied24h:
          sql<number>`count(*) filter (where ${tokenEvents.outcome} = 'denied' and ${last24h})`.mapWith(
            Number,
          ),
        requests24h:
          sql<number>`count(*) filter (where ${tokenEvents.outcome} in ('issued', 'denied') and ${last24h})`.mapWith(
            Number,
          ),
        activeApps24h:
          sql<number>`count(distinct ${tokenEvents.applicationId}) filter (where ${issued} and ${last24h})`.mapWith(
            Number,
          ),
      })
      .from(tokenEvents)
      .where(
        and(
          eq(tokenEvents.tenantId, tenantId),
          sql`${tokenEvents.createdAt} >= now() - interval '48 hours'`,
        ),
      ),
    db.select({ totalApps: count() }).from(applications).where(eq(applications.tenantId, tenantId)),
  ]);
  return { ...events, totalApps: apps.totalApps };
}

/** Delete events older than `retentionDays` across all tenants. Returns the deleted count. */
export async function purgeOldTokenEvents(retentionDays: number): Promise<number> {
  const result = await db
    .delete(tokenEvents)
    .where(lt(tokenEvents.createdAt, sql`now() - make_interval(days => ${retentionDays})`));
  const deleted = result.rowCount ?? 0;
  if (deleted > 0) logger.info({ deleted, retentionDays }, "Purged old token events");
  return deleted;
}
