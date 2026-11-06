import type { Context, MiddlewareHandler } from "hono";
import type { AppEnv } from "../app.js";
import { assertionClientId } from "../utils/client-assertion.js";
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
  /** Max live buckets per limiter; beyond it the oldest bucket is evicted (bounds memory). */
  maxKeys?: number;
}

/** Rate-limit bucket key derived from the trusted client IP (see getClientIp). */
export function ipKey(c: Context): string {
  return getClientIp(c);
}

/**
 * Per-client rate-limit key for OAuth endpoints that accept client credentials:
 * `client:{id}|ip:{ip}`. client_id is unauthenticated input, so keying on it alone
 * would let anyone who knows a public client_id exhaust its bucket and lock that
 * client out from every source; per-(client, IP) still bounds Argon2 work per
 * source without letting one source lock other sources out (the per-IP limiter,
 * `ipKey`, runs separately). Falls back to `ip:{ip}` when no client_id is found
 * (Basic header absent and no parsed form body cached on `c.var.formBody` — the
 * token route sets it before this runs).
 */
export function clientIdKey(c: Context<AppEnv>): string {
  const clientId =
    basicClientId(c.req.header("Authorization")) ??
    c.var.formBody?.client_id ??
    assertionClientId(c.var.formBody?.client_assertion);
  const ip = getClientIp(c);
  return clientId ? `client:${clientId}|ip:${ip}` : `ip:${ip}`;
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
  // This limiter's buckets in creation order (key -> resetAt). KVStore cannot
  // enumerate keys, so this index drives the expiry sweep and oldest-first eviction.
  const buckets = new Map<string, number>();

  return async (c, next) => {
    const now = Date.now();
    const key = opts.keyFn(c);
    // The store expires buckets at resetAt, so a missing entry means a fresh window.
    // shortcut: get+set is not atomic across awaits; concurrent first hits may undercount by a few, fine for an in-memory limiter, revisit with a Redis store (INCR).
    let entry = await store.get(key);
    if (!entry) {
      buckets.delete(key);
      if (buckets.size >= maxKeys) {
        for (const [k, resetAt] of buckets) {
          if (resetAt > now) continue;
          buckets.delete(k);
          await store.delete(k);
        }
      }
      // Never reject an unseen key: a flood of random keys must not lock out real clients.
      for (const oldest of buckets.keys()) {
        if (buckets.size < maxKeys) break;
        buckets.delete(oldest);
        await store.delete(oldest);
      }
      entry = { count: 0, resetAt: now + opts.windowMs };
      buckets.set(key, entry.resetAt);
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
