import type { Context, MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.js";
import { getClientIp } from "../utils/client-ip.js";
import { logSecurityEvent, SecurityEvent, SecuritySeverity } from "../utils/security-logger.js";
import { type KVStore, MemoryStore } from "../utils/store.js";

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

interface RateLimitOptions {
  /** Derives the bucket key from the request. */
  keyFn: (c: Context<AppEnv>) => string;
  max: number;
  windowMs: number;
  /** Bucket storage; defaults to a fresh in-memory store per limiter. */
  store?: KVStore<RateLimitEntry>;
  /** `oauth` = RFC 6749-style body + no-store headers (`/t`), `api` = management envelope. */
  errorBody?: "oauth" | "api";
  /** Max live buckets per limiter before new keys are shed (bounds memory). */
  maxKeys?: number;
}

/** Rate-limit bucket key derived from the trusted client IP (see getClientIp). */
export function ipKey(c: Context): string {
  return getClientIp(c);
}

/**
 * Rate-limit key for OAuth endpoints that accept client credentials.
 *
 * A pre-auth `client_id` is never used alone: an attacker who knows a client_id
 * must not be able to exhaust that client's quota from elsewhere. Claims are
 * always bound to the source IP: `ip:{ip}:client:{id}`, or `ip:{ip}` when no
 * client_id is found (Basic header absent and no parsed form body cached on
 * `c.var.formBody` — the token route is expected to set it before this runs).
 */
export function clientIdKey(c: Context<AppEnv>): string {
  const ip = getClientIp(c);
  const clientId = basicClientId(c.req.header("Authorization")) ?? c.var.formBody?.client_id;
  return clientId ? `ip:${ip}:client:${clientId}` : `ip:${ip}`;
}

function basicClientId(authHeader: string | undefined): string | undefined {
  if (!authHeader?.startsWith("Basic ")) return undefined;
  const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
  const colonIndex = decoded.indexOf(":");
  return colonIndex > 0 ? decoded.slice(0, colonIndex) : undefined;
}

function tooManyRequests(
  c: Context,
  retryAfterSeconds: number,
  errorBody: "oauth" | "api",
): Response {
  c.header("Retry-After", String(retryAfterSeconds));
  if (errorBody === "oauth") {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    return c.json({ error: "too_many_requests", error_description: "Rate limit exceeded" }, 429);
  }
  return c.json({ error: "rate_limited", error_description: "Rate limit exceeded" }, 429);
}

export function rateLimit(opts: RateLimitOptions): MiddlewareHandler<AppEnv> {
  const store = opts.store ?? new MemoryStore<RateLimitEntry>();
  const errorBody = opts.errorBody ?? "api";
  const maxKeys = opts.maxKeys ?? 20_000;

  return async (c, next) => {
    const now = Date.now();
    const key = opts.keyFn(c);
    // The store expires buckets at resetAt, so a missing entry means a fresh window.
    // shortcut: get+set is not atomic across awaits; concurrent first hits may undercount by a few, fine for an in-memory limiter, revisit with a Redis store (INCR).
    let entry = await store.get(key);
    if (!entry) {
      // Expired-but-unswept keys still count until the store's periodic sweep.
      if ((await store.size()) >= maxKeys) {
        return tooManyRequests(c, 60, errorBody);
      }
      entry = { count: 0, resetAt: now + opts.windowMs };
    }
    entry.count += 1;
    // ttl 0 would mean "never expire" in MemoryStore, so clamp to >= 1 ms
    await store.set(key, entry, Math.max(1, entry.resetAt - now));

    c.header("X-RateLimit-Limit", String(opts.max));
    c.header("X-RateLimit-Remaining", String(Math.max(0, opts.max - entry.count)));

    if (entry.count > opts.max) {
      logSecurityEvent({
        event: SecurityEvent.RATE_LIMIT_EXCEEDED,
        severity: SecuritySeverity.HIGH,
        sourceIp: ipKey(c),
        path: c.req.path,
        method: c.req.method,
        requestId: c.var.requestId,
        details: { key, count: entry.count, max: opts.max, windowMs: opts.windowMs },
      });
      return tooManyRequests(c, Math.max(1, Math.ceil((entry.resetAt - now) / 1000)), errorBody);
    }

    await next();
  };
}
