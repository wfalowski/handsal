import { serve } from "@hono/node-server";
import { createApp, createReadiness } from "./app.js";
import { env } from "./env.js";
import { startJobs, stopJobs } from "./jobs/index.js";
import { bootstrapAdmin } from "./services/bootstrap.js";
import { createLogger, rootLogger } from "./utils/logger.js";

const logger = createLogger("server");

let server: ReturnType<typeof serve> | null = null;
let dbPool: { end(): Promise<void> } | null = null;
let shuttingDown = false;

/** Close the HTTP server and drain the DB pool, then exit with `code`. */
function drainAndExit(code: number): void {
  stopJobs();

  const closeServer = (): Promise<void> =>
    new Promise((resolve) => {
      if (!server) {
        resolve();
        return;
      }
      server.close((err) => {
        if (err) logger.error({ err }, "Error closing HTTP server");
        resolve();
      });
    });

  closeServer()
    .then(() => dbPool?.end())
    .then(() => {
      logger.info({ code }, "Shutdown complete");
      process.exit(code);
    })
    .catch((err) => {
      logger.error({ err }, "Error during shutdown");
      process.exit(code === 0 ? 1 : code);
    });

  // Safety net: force exit if cleanup hangs (e.g. a stuck request).
  setTimeout(() => {
    logger.error("Shutdown timed out after 10s, forcing exit");
    process.exit(code === 0 ? 1 : code);
  }, 10_000).unref();
}

function shutdown(signal: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, "Graceful shutdown initiated");
  rootLogger.flush();
  drainAndExit(0);
}

/**
 * Crash handler for errors that escape the request pipeline (e.g. an idle pg
 * client error with no listener, or a stray unhandled rejection). Without this
 * Node terminates immediately, bypassing the log flush and pool drain.
 */
function handleFatal(err: unknown, context: string): void {
  logger.fatal({ err }, context);
  rootLogger.flush();
  if (shuttingDown) {
    process.exit(1);
    return;
  }
  shuttingDown = true;
  drainAndExit(1);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("uncaughtException", (err) => handleFatal(err, "Uncaught exception"));
process.on("unhandledRejection", (reason) => handleFatal(reason, "Unhandled promise rejection"));

async function main() {
  // Dynamic import: @handsal/db builds its pool from process.env at import time,
  // so it must load after ./env.js has run (see index.ts).
  const dbModule = await import("@handsal/db");
  dbPool = dbModule.pool;

  // Listen first: /health answers and /ready reports 503 "migrating" while DDL
  // runs, so orchestrators don't kill the container mid-migration.
  const readiness = createReadiness();
  const app = createApp({ readinessCheck: readiness.check });
  server = serve({ fetch: app.fetch, port: env.PORT }, (info) => {
    logger.info({ port: info.port }, "Server started");
  });

  logger.info("Running database migrations...");
  await dbModule.runMigrations();
  logger.info("Migrations complete");

  await bootstrapAdmin();

  startJobs();

  readiness.markReady();
  logger.info("Ready");
}

main().catch((err) => {
  logger.fatal({ err }, "Failed to start server");
  process.exit(1);
});
