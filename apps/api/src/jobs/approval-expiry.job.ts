import { expirePendingApprovals } from "../services/approval.service.js";
import type { Job } from "./index.js";

/** Every minute: move overdue pending approvals to `expired` so they reach the Resolved tab. */
export const approvalExpiryJob: Job = {
  name: "approval-expiry",
  intervalMs: 60_000,
  run: expirePendingApprovals,
};
