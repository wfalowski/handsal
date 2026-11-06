import type { MiddlewareHandler } from "hono";
import { getClientIp } from "../utils/client-ip.js";
import { createLogger } from "../utils/logger.js";

const logger = createLogger("http");

export const requestLogger: MiddlewareHandler = async (c, next) => {
  const start = performance.now();

  await next();

  const duration = Math.round(performance.now() - start);
  const status = c.res.status;
  const path = c.req.path;
  const method = c.req.method;

  // Skip noisy health/readiness probes
  if ((path === "/health" || path === "/ready") && status === 200) return;

  const logData = {
    type: "http_request" as const,
    requestId: c.get("requestId"),
    method,
    path,
    route: c.req.routePath,
    status,
    duration,
    ip: getClientIp(c),
    // Only worth the field cost on failed requests — omit for successful ones.
    ...(status >= 400 ? { userAgent: c.req.header("user-agent") } : {}),
  };

  if (status >= 500) {
    logger.error(logData, `${method} ${path} ${status} ${duration}ms`);
  } else if (status >= 400) {
    logger.warn(logData, `${method} ${path} ${status} ${duration}ms`);
  } else {
    logger.info(logData, `${method} ${path} ${status} ${duration}ms`);
  }
};
