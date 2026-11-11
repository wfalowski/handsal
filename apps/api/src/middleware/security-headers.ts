import type { MiddlewareHandler } from "hono";
import { env } from "../env.js";

const API_CSP = "default-src 'none'; frame-ancestors 'none'";
const SPA_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'";

// Issuer endpoints only. /t/<tenantId>/applications and the other admin URLs are SPA
// routes; a refresh must get index.html, not the tenant resolver.
const TENANT_API = /^\/t\/[^/]+\/(?:oauth|\.well-known)(?:\/|$)/;

/** Paths served by the API (JSON); everything else belongs to the admin SPA. */
export function isApiPath(path: string): boolean {
  return (
    path === "/api" ||
    path.startsWith("/api/") ||
    TENANT_API.test(path) ||
    path === "/health" ||
    path === "/ready" ||
    path === "/instance"
  );
}

export const securityHeaders: MiddlewareHandler = async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (env.NODE_ENV === "production") {
    c.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
  // Strict CSP for JSON endpoints; SPA policy for the admin UI's HTML/assets
  c.header("Content-Security-Policy", isApiPath(c.req.path) ? API_CSP : SPA_CSP);
};
