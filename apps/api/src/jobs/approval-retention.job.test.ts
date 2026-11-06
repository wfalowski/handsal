// Integration test: real Postgres.
import { approvalRequests, db, runMigrations } from "@handsal/db";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createApplication,
  createApprovalRequest,
  createResourceWithScopes,
  createTenant,
  truncateAll,
} from "../test/factories.js";
import { approvalRetentionJob } from "./approval-retention.job.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("approval-retention job", () => {
  it("deletes only resolved rows past the retention window", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id, { kind: "agent" });
    const { resource } = await createResourceWithScopes(tenant.id, "https://api.acme.io/payments", [
      "payments:read",
    ]);
    const old = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000);
    const make = (over = {}) => createApprovalRequest(tenant.id, application.id, resource.id, over);
    await make({ status: "denied", expiresAt: old, decidedAt: old });
    await make({ status: "expired", expiresAt: old });
    const stalePending = await make({ expiresAt: old });
    const recent = await make({ status: "approved", decidedAt: new Date() });

    expect(await approvalRetentionJob.run()).toBe(2);
    const ids = (await db.select().from(approvalRequests)).map((r) => r.id).sort();
    expect(ids).toEqual([stalePending.id, recent.id].sort());
    expect(approvalRetentionJob.intervalMs).toBe(60 * 60 * 1000);
  });
});
