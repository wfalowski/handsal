import { BlockList, isIP } from "node:net";
import { getConnInfo } from "@hono/node-server/conninfo";
import type { Context } from "hono";
import { env } from "../env.js";

// Immediate peers allowed to supply forwarding headers. A public TCP peer is
// absent on purpose: with TRUST_PROXY=true a direct caller must not spoof.
const trustedProxyNets = new BlockList();
for (const [net, prefix] of [
  ["127.0.0.0", 8],
  ["10.0.0.0", 8],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["169.254.0.0", 16],
  ["100.64.0.0", 10],
] as const) {
  trustedProxyNets.addSubnet(net, prefix, "ipv4");
}
trustedProxyNets.addAddress("::1", "ipv6");
for (const [net, prefix] of [
  ["fc00::", 7],
  ["fe80::", 10],
] as const) {
  trustedProxyNets.addSubnet(net, prefix, "ipv6");
}

/** Brackets, a trailing dot, then `::ffff:a.b.c.d` → `a.b.c.d` for BlockList. */
function normalizePeer(address: string): string {
  let ip = address.trim();
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  if (ip.endsWith(".")) ip = ip.slice(0, -1);
  return ip.replace(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i, "$1");
}

function isTrustedProxyPeer(address: string): boolean {
  const ip = normalizePeer(address);
  const family = isIP(ip);
  if (family === 4) return trustedProxyNets.check(ip, "ipv4");
  if (family === 6) return trustedProxyNets.check(ip, "ipv6");
  return false;
}

function readSocketPeer(c: Context): string | undefined {
  try {
    const address = getConnInfo(c).remote.address;
    if (address) return address;
  } catch {
    // getConnInfo is unavailable outside the node-server runtime (e.g. unit tests).
  }
  return undefined;
}

/** Rightmost trusted XFF entry, else X-Real-IP. Undefined when neither is usable. */
function readForwardedIp(c: Context): string | undefined {
  const xff = c.req.header("x-forwarded-for");
  if (xff) {
    const parts = xff
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    if (parts.length > 0) {
      // Skip trusted-proxy hops appended on the right. Clamp so a short header
      // cannot index before the start of the list.
      const idx = Math.max(0, parts.length - env.TRUST_PROXY_HOP_COUNT);
      const ip = parts[idx];
      if (ip) return ip;
    }
  }
  const realIp = c.req.header("x-real-ip")?.trim();
  if (realIp) return realIp;
  return undefined;
}

/**
 * Resolve the trusted client IP for rate limiting, CIDR checks, and audit logging.
 *
 * Forwarding headers are honored only when `TRUST_PROXY=true` and the immediate
 * TCP peer is a trusted proxy: IPv4 loopback (127/8), RFC1918, link-local
 * (169.254/16), CGNAT (100.64/10), IPv6 loopback (::1), unique-local (fc00::/7),
 * or IPv6 link-local (fe80::/10). IPv4-mapped IPv6 is unwrapped before that check.
 * `X-Forwarded-For` is counted from the right by `TRUST_PROXY_HOP_COUNT`; leftmost
 * entries are client-controlled. If XFF is absent, `X-Real-IP` is used.
 *
 * A public peer, `TRUST_PROXY=false`, or missing forwarding headers returns the
 * socket address. If the peer cannot be determined, the result is `"unknown"`.
 */
export function getClientIp(c: Context): string {
  const peer = readSocketPeer(c);
  if (!peer) return "unknown";
  if (env.TRUST_PROXY === "true" && isTrustedProxyPeer(peer)) {
    return readForwardedIp(c) ?? peer;
  }
  return peer;
}
