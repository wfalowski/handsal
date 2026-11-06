import { createLogger } from "../utils/logger.js";
import { keyRotationJob } from "./key-rotation.job.js";
import { revokedCleanupJob } from "./revoked-cleanup.job.js";
import { tokenEventsRetentionJob } from "./token-events-retention.job.js";

const logger = createLogger("jobs");

export interface Job {
  name: string;
  intervalMs: number;
  run: () => Promise<unknown>;
}

// Register interval jobs here.
const jobs: Job[] = [keyRotationJob, tokenEventsRetentionJob, revokedCleanupJob];

const timers: ReturnType<typeof setInterval>[] = [];

function runSafely(job: Job): void {
  job.run().catch((err) => {
    logger.error({ err, job: job.name }, "Job failed");
  });
}

/** Run every job once now, then on its interval. Errors are logged, never thrown. */
export function startJobs(): void {
  if (timers.length > 0) return;
  for (const job of jobs) {
    runSafely(job);
    const timer = setInterval(() => runSafely(job), job.intervalMs);
    timer.unref();
    timers.push(timer);
  }
}

export function stopJobs(): void {
  for (const timer of timers) clearInterval(timer);
  timers.length = 0;
}
