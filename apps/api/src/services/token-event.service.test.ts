// Integration test: real Postgres, no HTTP app.
import { randomUUID } from "node:crypto";
import { db, runMigrations, tokenEvents } from "@handsal/db";
import { sql } from "drizzle-orm";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApplication, createTenant, truncateAll } from "../test/factories.js";
import {
  getTokenStats,
  listTasks,
  listTokenEvents,
  purgeOldTokenEvents,
  recordTokenEvent,
  type TokenEventsQuery,
} from "./token-event.service.js";

const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000);
const query = (over: Partial<TokenEventsQuery> = {}): TokenEventsQuery => ({ limit: 50, ...over });

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("listTokenEvents", () => {
  it("pages newest first with a keyset cursor, including rows sharing a timestamp", async () => {
    const tenant = await createTenant();
    const other = await createTenant();
    // All rows in one statement share created_at (now() is per transaction).
    await db.insert(tokenEvents).values(
      Array.from({ length: 5 }, (_, i) => ({
        tenantId: tenant.id,
        outcome: "issued" as const,
        jti: `jti-${i}`,
      })),
    );
    await recordTokenEvent({ tenantId: other.id, outcome: "issued", jti: "foreign" });

    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await listTokenEvents(tenant.id, query({ limit: 2, cursor }));
      expect(page.items.length).toBeLessThanOrEqual(2);
      seen.push(...page.items.map((e) => e.jti ?? ""));
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    expect(seen).toEqual(["jti-4", "jti-3", "jti-2", "jti-1", "jti-0"]);
  });

  it("filters by outcome, application, since and q", async () => {
    const tenant = await createTenant();
    const appId = randomUUID();
    await db.insert(tokenEvents).values([
      {
        tenantId: tenant.id,
        outcome: "issued",
        applicationId: appId,
        applicationClientId: "app_alpha",
        jti: "abc-1",
      },
      {
        tenantId: tenant.id,
        outcome: "denied",
        applicationClientId: "app_beta",
        reason: "bad_secret",
      },
      {
        tenantId: tenant.id,
        outcome: "issued",
        applicationClientId: "app_old",
        createdAt: hoursAgo(72),
      },
    ]);

    const ids = async (q: Partial<TokenEventsQuery>) =>
      (await listTokenEvents(tenant.id, query(q))).items.map((e) => e.applicationClientId).sort();

    expect(await ids({ outcome: "denied" })).toEqual(["app_beta"]);
    expect(await ids({ applicationId: appId })).toEqual(["app_alpha"]);
    expect(await ids({ since: hoursAgo(24).toISOString() })).toEqual(["app_alpha", "app_beta"]);
    expect(await ids({ q: "BETA" })).toEqual(["app_beta"]);
    expect(await ids({ q: "abc" })).toEqual(["app_alpha"]);
    expect(await ids({ q: "%" })).toEqual([]);
  });

  it("q also matches the application name", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id, { name: "Billing Gateway" });
    await recordTokenEvent({
      tenantId: tenant.id,
      outcome: "issued",
      applicationId: application.id,
      applicationClientId: application.clientId,
    });
    await recordTokenEvent({
      tenantId: tenant.id,
      outcome: "denied",
      applicationClientId: "app_x",
    });

    const { items } = await listTokenEvents(tenant.id, query({ q: "billing gate" }));
    expect(items.map((e) => e.applicationId)).toEqual([application.id]);
  });

  it("returns DTOs with ISO dates and rejects a garbage cursor", async () => {
    const tenant = await createTenant();
    await recordTokenEvent({
      tenantId: tenant.id,
      outcome: "issued",
      scopes: ["a", "b"],
      expiresAt: new Date("2030-01-01T00:00:00Z"),
    });
    const { items, nextCursor } = await listTokenEvents(tenant.id, query());
    expect(nextCursor).toBeNull();
    expect(items[0]).toMatchObject({
      id: "1",
      outcome: "issued",
      scopes: ["a", "b"],
      expiresAt: "2030-01-01T00:00:00.000Z",
      createdAt: expect.stringMatching(/Z$/),
    });
    await expect(listTokenEvents(tenant.id, query({ cursor: "nope" }))).rejects.toMatchObject({
      statusCode: 400,
      errorCode: "invalid_cursor",
    });
  });
});

describe("task activity", () => {
  it("stores and emits taskId/actorSub, null when absent, and ?taskId filters exactly", async () => {
    const tenant = await createTenant();
    await recordTokenEvent({
      tenantId: tenant.id,
      outcome: "issued",
      taskId: "run_01JBXA3K",
      actorSub: "user:42",
    });
    await recordTokenEvent({ tenantId: tenant.id, outcome: "issued", taskId: "run_01JBXA3" });
    await recordTokenEvent({ tenantId: tenant.id, outcome: "issued" });

    const all = (await listTokenEvents(tenant.id, query())).items;
    expect(all.map((e) => [e.taskId, e.actorSub])).toEqual([
      [null, null],
      ["run_01JBXA3", null],
      ["run_01JBXA3K", "user:42"],
    ]);
    const filtered = (await listTokenEvents(tenant.id, query({ taskId: "run_01JBXA3K" }))).items;
    expect(filtered.map((e) => e.taskId)).toEqual(["run_01JBXA3K"]);
  });

  it("groups a task: distinct counts, scope union, first/last seen, mixed outcomes", async () => {
    const tenant = await createTenant();
    const appId = randomUUID();
    const base = { tenantId: tenant.id, applicationId: appId, applicationClientId: "app_agent" };
    await db.insert(tokenEvents).values([
      {
        ...base,
        outcome: "issued",
        taskId: "t1",
        actorSub: "user:7",
        scopes: ["a", "b"],
        createdAt: hoursAgo(3),
      },
      { ...base, outcome: "issued", taskId: "t1", scopes: ["b", "c"], createdAt: hoursAgo(2) },
      { ...base, outcome: "denied", taskId: "t1", scopes: [], createdAt: hoursAgo(1) },
      { ...base, outcome: "issued", scopes: ["z"], createdAt: hoursAgo(1) },
    ]);

    expect(await listTasks(tenant.id, { limit: 20 })).toEqual([
      {
        taskId: "t1",
        applicationId: appId,
        applicationClientId: "app_agent",
        actorSub: "user:7",
        scopes: ["a", "b", "c"],
        tokenCount: 3,
        deniedCount: 1,
        firstSeenAt: expect.any(String),
        lastSeenAt: expect.any(String),
      },
    ]);
    const [t] = await listTasks(tenant.id, { limit: 20 });
    expect(Date.parse(t.lastSeenAt) - Date.parse(t.firstSeenAt)).toBeCloseTo(2 * 3600_000, -3);
  });

  it("orders by last activity, honours applicationId and limit, drops events older than 24 h", async () => {
    const tenant = await createTenant();
    const [a, b] = [randomUUID(), randomUUID()];
    const ev = (taskId: string, applicationId: string, createdAt: Date) => ({
      tenantId: tenant.id,
      outcome: "issued" as const,
      taskId,
      applicationId,
      createdAt,
    });
    await db
      .insert(tokenEvents)
      .values([
        ev("old", a, hoursAgo(5)),
        ev("new", b, hoursAgo(1)),
        ev("mid", a, hoursAgo(3)),
        ev("old", a, hoursAgo(2)),
        ev("stale", a, hoursAgo(25)),
      ]);

    const ids = async (q: { applicationId?: string; limit?: number }) =>
      (await listTasks(tenant.id, { limit: 20, ...q })).map((t) => t.taskId);
    expect(await ids({})).toEqual(["new", "old", "mid"]);
    expect(await ids({ applicationId: a })).toEqual(["old", "mid"]);
    expect(await ids({ limit: 1 })).toEqual(["new"]);
  });

  it("never returns another tenant's tasks", async () => {
    const [tenantA, tenantB] = [await createTenant(), await createTenant()];
    await recordTokenEvent({ tenantId: tenantB.id, outcome: "issued", taskId: "secret-task" });
    await recordTokenEvent({ tenantId: tenantA.id, outcome: "issued", taskId: "mine" });
    expect((await listTasks(tenantA.id, { limit: 20 })).map((t) => t.taskId)).toEqual(["mine"]);
    expect((await listTokenEvents(tenantA.id, query({ taskId: "secret-task" }))).items).toEqual([]);
  });
});

describe("getTokenStats", () => {
  it("counts the last 24 h, the 24 h before, distinct active apps and all apps", async () => {
    const tenant = await createTenant();
    await createApplication(tenant.id);
    await createApplication(tenant.id);
    await createApplication(tenant.id);
    const [a, b] = [randomUUID(), randomUUID()];
    const ev = (
      outcome: "issued" | "denied" | "revoked",
      createdAt: Date,
      applicationId?: string,
    ) => ({
      tenantId: tenant.id,
      outcome,
      createdAt,
      applicationId,
    });
    await db
      .insert(tokenEvents)
      .values([
        ev("issued", hoursAgo(1), a),
        ev("issued", hoursAgo(2), a),
        ev("issued", hoursAgo(3), b),
        ev("denied", hoursAgo(1)),
        ev("revoked", hoursAgo(1), a),
        ev("issued", hoursAgo(30), b),
        ev("issued", hoursAgo(60), b),
      ]);
    const other = await createTenant();
    await recordTokenEvent({ tenantId: other.id, outcome: "issued" });

    expect(await getTokenStats(tenant.id)).toEqual({
      issued24h: 3,
      issuedPrev24h: 1,
      denied24h: 1,
      requests24h: 4,
      activeApps24h: 2,
      totalApps: 3,
    });
  });
});

describe("purgeOldTokenEvents", () => {
  it("deletes only events older than the retention window", async () => {
    const tenant = await createTenant();
    await db.insert(tokenEvents).values([
      { tenantId: tenant.id, outcome: "issued", createdAt: hoursAgo(31 * 24) },
      { tenantId: tenant.id, outcome: "issued", createdAt: hoursAgo(29 * 24) },
    ]);
    expect(await purgeOldTokenEvents(30)).toBe(1);
    const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(tokenEvents);
    expect(n).toBe(1);
  });
});

describe("recordTokenEvent", () => {
  it("swallows insert failures", async () => {
    await expect(
      recordTokenEvent({ tenantId: randomUUID(), outcome: "denied" }),
    ).resolves.toBeUndefined();
  });
});
