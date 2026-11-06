import { DEFAULTS } from "@handsal/shared";
import { purgeResolvedApprovals } from "../services/approval.service.js";
import type { Job } from "./index.js";

/** Hourly: delete resolved approvals older than `APPROVAL_RETENTION_DAYS`, 1000 rows per run. */
export const approvalRetentionJob: Job = {
  name: "approval-retention",
  intervalMs: 60 * 60 * 1000,
  run: () => purgeResolvedApprovals(DEFAULTS.APPROVAL_RETENTION_DAYS),
};
