import { getConnInfo } from "@hono/node-server/conninfo";
import type { Context } from "hono";
import { env } from "../env.js";

/**
 * Resolve the trusted client IP for rate limiting and audit logging.
 *
 * When `TRUST_PROXY=true` (the app sits behind a reverse proxy), the client IP is
 * read from `X-Forwarded-For` counting from the RIGHT: each proxy appends the
 * address it received the request from, so the entry `TRUST_PROXY_HOP_COUNT`
 * positions from the end is the address our outermost trusted proxy actually
 * observed. The leftmost XFF entries are attacker-supplied and must never be
 * trusted (the previous implementation used `split(",")[0]`, which let a client
 * spoof its own source IP to bypass IP-keyed limits and forge audit logs).
 *
 * When `TRUST_PROXY=false` (no proxy — local/dev), fall back to the real socket
 * peer address so per-IP limiting still works per distinct caller instead of
 * collapsing everyone into a single `"unknown"` bucket.
 */
export function getClientIp(c: Context): string {
  if (env.TRUST_PROXY === "true") {
    const xff = c.req.header("x-forwarded-for");
    if (xff) {
      const parts = xff
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean);
      if (parts.length > 0) {
        // Skip the trusted-proxy hops appended on the right; take the address the
        // outermost trusted proxy saw. Clamp so a short/spoofed header can't index
        // before the start of the list.
        const idx = Math.max(0, parts.length - env.TRUST_PROXY_HOP_COUNT);
        const ip = parts[idx];
        if (ip) return ip;
      }
    }
    const realIp = c.req.header("x-real-ip");
    if (realIp) return realIp.trim();
  }

  try {
    const address = getConnInfo(c).remote.address;
    if (address) return address;
  } catch {
    // getConnInfo is unavailable outside the node-server runtime (e.g. unit tests).
  }
  return "unknown";
}
