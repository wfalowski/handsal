import { env } from "../env.js";
import { purgeOldTokenEvents } from "../services/token-event.service.js";
import type { Job } from "./index.js";

/** Daily: delete token events older than `TOKEN_EVENTS_RETENTION_DAYS`. */
export const tokenEventsRetentionJob: Job = {
  name: "token-events-retention",
  intervalMs: 24 * 60 * 60 * 1000,
  run: () => purgeOldTokenEvents(env.TOKEN_EVENTS_RETENTION_DAYS),
};
