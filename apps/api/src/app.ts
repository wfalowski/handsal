import crypto from "node:crypto";
import { createRequire } from "node:module";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { env } from "./env.js";
import { errorHandler } from "./middleware/error-handler.js";
import { requestLogger } from "./middleware/request-logger.js";
import { securityHeaders } from "./middleware/security-headers.js";
import { managementRoutes } from "./routes/management/index.js";
import { oauthRoutes } from "./routes/oauth/index.js";
import { createLogger } from "./utils/logger.js";

export type AppEnv = {
  Variables: {
    requestId: string;
    /** Parsed urlencoded body cached by OAuth routes (read by `clientIdKey`). */
    formBody?: Record<string, string>;
  };
};

export interface AppOptions {
  /** Resolves when the database is reachable; rejects otherwise. */
  readinessCheck?: () => Promise<void>;
}

const logger = createLogger("app");

// Resolves to apps/api/package.json from both src/ (tsx) and dist/ (node).
const { version } = createRequire(import.meta.url)("../package.json") as { version: string };

async function defaultReadinessCheck(): Promise<void> {
  const { pool } = await import("@handsal/db");
  await pool.query("select 1");
}

export function createApp({ readinessCheck = defaultReadinessCheck }: AppOptions = {}) {
  const app = new Hono<AppEnv>();

  // Request correlation ID
  app.use("/*", async (c, next) => {
    const requestId = c.req.header("x-request-id") ?? crypto.randomUUID();
    c.set("requestId", requestId);
    await next();
    c.header("X-Request-Id", requestId);
  });

  // HTTP request logging (after requestId is set)
  app.use("/*", requestLogger);
  app.use("/*", securityHeaders);

  // CORS only for the management API; OAuth endpoints are server-to-server.
  app.use(
    "/api/*",
    cors({
      origin: env.CORS_ORIGINS.split(",").map((o) => o.trim()),
      allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
      credentials: true,
    }),
  );

  // Body-size limits (before route handlers buffer the body). The token endpoint
  // reads its form body before client authentication, so an unbounded body is an
  // unauthenticated memory-exhaustion vector.
  app.use(
    "/t/*",
    bodyLimit({
      maxSize: 16 * 1024,
      onError: (c) =>
        c.json({ error: "invalid_request", error_description: "Request body too large" }, 413),
    }),
  );
  app.use(
    "/api/*",
    bodyLimit({
      maxSize: 512 * 1024,
      onError: (c) =>
        c.json({ error: "payload_too_large", error_description: "Request body too large" }, 413),
    }),
  );

  app.get("/health", (c) => c.json({ status: "ok", version }));

  app.get("/ready", async (c) => {
    try {
      await readinessCheck();
      return c.json({ status: "ok" });
    } catch (err) {
      logger.warn({ err, requestId: c.var.requestId }, "Readiness check failed");
      return c.json({ status: "db_unavailable" }, 503);
    }
  });

  // OAuth endpoints per tenant (token, introspect, revoke, discovery, jwks)
  app.route("/t/:slug", oauthRoutes);

  if (env.ENABLE_ADMIN_PANEL === "true") {
    app.route("/api", managementRoutes);

    // In production, serve the built admin SPA (copied to ./public)
    if (env.NODE_ENV === "production") {
      app.use("/*", serveStatic({ root: "./public" }));
      app.get("/*", serveStatic({ root: "./public", path: "index.html" }));
    }
  } else {
    app.all("/api/*", (c) =>
      c.json({ error: "not_found", error_description: "Admin panel is disabled" }, 404),
    );
  }

  app.notFound((c) => c.json({ error: "not_found", error_description: "Not found" }, 404));
  app.onError(errorHandler);

  return app;
}

export const app = createApp();
