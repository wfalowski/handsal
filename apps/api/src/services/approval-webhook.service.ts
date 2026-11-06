import { createHmac } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import type { ApprovalDto } from "@handsal/shared";
import { APPROVAL_WEBHOOK } from "@handsal/shared";
import { env } from "../env.js";
import { decryptPrivateKey } from "../utils/crypto.js";
import { createLogger } from "../utils/logger.js";
import type { Tenant } from "./tenant.service.js";

const logger = createLogger("approval-webhook");

/** Admin UI page listing the tenant's approval queue. */
export const approvalsLinkFor = (tenantId: string) => `${env.PUBLIC_URL}/t/${tenantId}/approvals`;

/** Slack incoming webhooks reject arbitrary JSON, so they get a `{ text }` body instead. */
export function webhookBody(url: string, tenant: Tenant, approval: ApprovalDto): string {
  const link = approvalsLinkFor(tenant.id);
  if (new URL(url).hostname.endsWith(APPROVAL_WEBHOOK.SLACK_HOST_SUFFIX)) {
    const task = approval.taskId ? ` (task ${approval.taskId})` : "";
    return JSON.stringify({
      text: `Approval needed: ${approval.applicationName} wants ${approval.scopes.join(", ")} on ${approval.audience}${task}. Review: <${link}|Approvals>`,
    });
  }
  return JSON.stringify({
    type: APPROVAL_WEBHOOK.EVENT_PENDING,
    approval,
    tenant: { id: tenant.id, slug: tenant.slug },
    links: { approvals: link },
  });
}

/**
 * POST the pending approval to the tenant's webhook. Never throws; one retry on a network error,
 * timeout or 5xx, none on 4xx. Callers fire it without awaiting.
 * Trade-off: a process exit before delivery loses the notification; the UI queue is the source of truth.
 */
export async function notifyApprovalPending(tenant: Tenant, approval: ApprovalDto): Promise<void> {
  const url = tenant.approvalWebhookUrl;
  if (!url) return;
  const log = { tenantId: tenant.id, approvalId: approval.id };
  try {
    const body = webhookBody(url, tenant, approval);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      [APPROVAL_WEBHOOK.EVENT_HEADER]: APPROVAL_WEBHOOK.EVENT_PENDING,
    };
    if (tenant.approvalWebhookSecretEnc) {
      const secret = decryptPrivateKey(tenant.approvalWebhookSecretEnc, env.KEY_ENCRYPTION_SECRET);
      headers[APPROVAL_WEBHOOK.SIGNATURE_HEADER] =
        `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
    }
    for (let attempt = 1; ; attempt++) {
      let failure: unknown;
      try {
        const res = await fetch(url, {
          method: "POST",
          headers,
          body,
          // A redirect could leave the admin-approved destination (and https).
          redirect: "manual",
          signal: AbortSignal.timeout(APPROVAL_WEBHOOK.TIMEOUT_MS),
        });
        await res.body?.cancel();
        if (res.status < 500) {
          if (!res.ok) logger.warn({ ...log, status: res.status }, "Approval webhook rejected");
          return;
        }
        failure = `HTTP ${res.status}`;
      } catch (err) {
        failure = err;
      }
      if (attempt >= 2) {
        logger.warn({ ...log, err: failure }, "Approval webhook delivery failed");
        return;
      }
      await sleep(APPROVAL_WEBHOOK.RETRY_DELAY_MS);
    }
  } catch (err) {
    logger.warn({ ...log, err }, "Approval webhook delivery failed");
  }
}
