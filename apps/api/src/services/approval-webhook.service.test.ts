// Integration test: real Postgres + a local Hono receiver on an ephemeral port.
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { applications, approvalRequests, db, runMigrations, scopes, tenants } from "@handsal/db";
import type { ApprovalDto } from "@handsal/shared";
import { serve } from "@hono/node-server";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createApplication,
  createApprovalRule,
  createResourceWithScopes,
  createTenant,
  grant,
  truncateAll,
} from "../test/factories.js";
import { notifyApprovalPending, webhookBody } from "./approval-webhook.service.js";
import type { AuthenticatedApplication } from "./client-auth.service.js";
import { getTenantById, updateTenant } from "./tenant.service.js";
import { issueToken, type PendingApproval } from "./token.service.js";

const AUD = "https://api.acme.io/payments";
const SECRET = "webhook-secret-0123456789";

let received: { headers: Headers; body: string }[] = [];
let replyStatus = 200;
const receiver = new Hono().post("/hook", async (c) => {
  received.push({ headers: c.req.raw.headers, body: await c.req.text() });
  return c.body(null, replyStatus as 200);
});
const server = serve({ fetch: receiver.fetch, port: 0, hostname: "127.0.0.1" });
const hookUrl = () => `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`;

beforeAll(async () => {
  await runMigrations();
});
beforeEach(async () => {
  await truncateAll();
  received = [];
  replyStatus = 200;
});
afterAll(() => {
  server.close();
});

async function tenantWithWebhook(url: string, secret: string | null = SECRET) {
  const t = await createTenant();
  await updateTenant(t.id, { approvalWebhookSecret: secret });
  // Loopback receiver: written directly, past updateTenant's internal-address guard.
  await db.update(tenants).set({ approvalWebhookUrl: url }).where(eq(tenants.id, t.id));
  const tenant = await getTenantById(t.id);
  if (!tenant) throw new Error("tenant missing");
  return tenant;
}

const dto: ApprovalDto = {
  id: "33333333-3333-4333-8333-333333333333",
  applicationId: "44444444-4444-4444-8444-444444444444",
  applicationName: "Refunder",
  clientId: "client-1",
  audience: AUD,
  scopes: ["payments:write"],
  actorHint: "alice",
  taskId: "run-1",
  justification: "refund batch",
  status: "pending",
  expiresAt: new Date().toISOString(),
  createdAt: new Date().toISOString(),
  decidedAt: null,
  decidedBy: null,
};

describe("notifyApprovalPending", () => {
  it("signs the exact body", async () => {
    const tenant = await tenantWithWebhook(hookUrl());
    await notifyApprovalPending(tenant, dto);
    expect(received).toHaveLength(1);
    const { headers, body } = received[0];
    const expected = `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`;
    expect(headers.get("x-handsal-signature")).toBe(expected);
    expect(headers.get("x-handsal-event")).toBe("approval.pending");
    expect(headers.get("content-type")).toBe("application/json");
    expect(JSON.parse(body)).toEqual({
      type: "approval.pending",
      approval: dto,
      tenant: { id: tenant.id, slug: tenant.slug },
      links: { approvals: `https://test.example.com/t/${tenant.id}/approvals` },
    });
  });

  it("omits the signature header when no secret is configured", async () => {
    const tenant = await tenantWithWebhook(hookUrl(), null);
    await notifyApprovalPending(tenant, dto);
    expect(received).toHaveLength(1);
    expect(received[0].headers.has("x-handsal-signature")).toBe(false);
  });

  it("sends a Slack text payload to hooks.slack.com", async () => {
    const tenant = await tenantWithWebhook(hookUrl());
    const body = JSON.parse(webhookBody("https://hooks.slack.com/services/T/B/X", tenant, dto));
    expect(Object.keys(body)).toEqual(["text"]);
    expect(body.text).toContain("Refunder wants payments:write on https://api.acme.io/payments");
    expect(body.text).toContain(`https://test.example.com/t/${tenant.id}/approvals`);
  });

  it("retries once on 500 and gives up", async () => {
    replyStatus = 500;
    const tenant = await tenantWithWebhook(hookUrl());
    await notifyApprovalPending(tenant, dto);
    expect(received).toHaveLength(2);
  }, 10_000);

  it("does not retry a 400", async () => {
    replyStatus = 400;
    const tenant = await tenantWithWebhook(hookUrl());
    await notifyApprovalPending(tenant, dto);
    expect(received).toHaveLength(1);
  });

  it("an unreachable receiver resolves without throwing", async () => {
    const tenant = await tenantWithWebhook("http://127.0.0.1:1/hook");
    await expect(notifyApprovalPending(tenant, dto)).resolves.toBeUndefined();
  }, 10_000);
});

describe("token request path", () => {
  async function agentSetup(webhookUrl: string) {
    const tenant = await tenantWithWebhook(webhookUrl);
    const { application } = await createApplication(tenant.id, { kind: "agent" });
    const { scopes: created } = await createResourceWithScopes(tenant.id, AUD, ["payments:write"]);
    await db.update(scopes).set({ agentPolicy: "approval" }).where(eq(scopes.id, created[0].id));
    await grant(tenant.id, application.id, [created[0].id]);
    const [row] = await db.select().from(applications).where(eq(applications.id, application.id));
    const { clientSecretHash: _c, previousSecretHash: _p, ...app } = row;
    const request = (taskId?: string) =>
      issueToken(
        tenant,
        app as AuthenticatedApplication,
        { audience: AUD, requestedScopes: ["payments:write"], taskId },
        { sourceIp: "203.0.113.7" },
      ) as Promise<PendingApproval>;
    return { tenant, scope: created[0], request };
  }

  it("a new pending request posts the approval DTO", async () => {
    const s = await agentSetup(hookUrl());
    const { approvalId } = await s.request("run-5");
    await vi.waitFor(() => expect(received).toHaveLength(1));
    const payload = JSON.parse(received[0].body);
    expect(payload.approval).toMatchObject({ id: approvalId, status: "pending", taskId: "run-5" });
    expect(payload.tenant.slug).toBe(s.tenant.slug);
  });

  it("reusing an identical pending request does not re-fire the webhook", async () => {
    const s = await agentSetup(hookUrl());
    const a = await s.request("run-5");
    const b = await s.request("run-5");
    expect(b.approvalId).toBe(a.approvalId);
    await vi.waitFor(() => expect(received).toHaveLength(1));
    // A second delivery to the local receiver would land well within this window.
    await new Promise((r) => setTimeout(r, 300));
    expect(received).toHaveLength(1);
  });

  it("no webhook is sent for a rule-approved row", async () => {
    const s = await agentSetup(hookUrl());
    await createApprovalRule(s.tenant.id, s.scope.id);
    const { approvalId } = await s.request();
    const [row] = await db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.id, approvalId));
    expect(row.status).toBe("approved");
    // A pending delivery to the local receiver lands well within this window.
    await new Promise((r) => setTimeout(r, 300));
    expect(received).toHaveLength(0);
  });

  it("a webhook failure does not fail the approval request", async () => {
    const s = await agentSetup("http://127.0.0.1:1/hook");
    const { approvalId } = await s.request();
    const [row] = await db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.id, approvalId));
    expect(row.status).toBe("pending");
  });
});
