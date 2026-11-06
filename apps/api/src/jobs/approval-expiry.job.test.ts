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
import { approvalExpiryJob } from "./approval-expiry.job.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

describe("approval-expiry job", () => {
  it("marks only overdue pending rows expired", async () => {
    const tenant = await createTenant();
    const { application } = await createApplication(tenant.id, { kind: "agent" });
    const { resource } = await createResourceWithScopes(tenant.id, "https://api.acme.io/payments", [
      "payments:read",
    ]);
    const past = new Date(Date.now() - 1000);
    const make = (over = {}) => createApprovalRequest(tenant.id, application.id, resource.id, over);
    const overdue = await make({ expiresAt: past });
    const live = await make();
    const approved = await make({ status: "approved", expiresAt: past });

    expect(await approvalExpiryJob.run()).toBe(1);
    const rows = await db.select().from(approvalRequests);
    expect(Object.fromEntries(rows.map((r) => [r.id, r.status]))).toEqual({
      [overdue.id]: "expired",
      [live.id]: "pending",
      [approved.id]: "approved",
    });
    expect(approvalExpiryJob.intervalMs).toBe(60_000);
  });
});
