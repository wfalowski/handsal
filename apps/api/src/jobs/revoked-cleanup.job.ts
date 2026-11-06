import { purgeExpiredRevocations } from "../services/revocation.service.js";
import type { Job } from "./index.js";

/** Hourly: delete revoked-token rows whose token has expired anyway. */
export const revokedCleanupJob: Job = {
  name: "revoked-cleanup",
  intervalMs: 60 * 60 * 1000,
  run: purgeExpiredRevocations,
};
