import type { Context } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockEnv, mockGetConnInfo } = vi.hoisted(() => ({
  mockEnv: { TRUST_PROXY: "true", TRUST_PROXY_HOP_COUNT: 1 },
  mockGetConnInfo: vi.fn(),
}));

vi.mock("../env.js", () => ({ env: mockEnv }));
vi.mock("@hono/node-server/conninfo", () => ({ getConnInfo: mockGetConnInfo }));

import { getClientIp } from "./client-ip.js";

function ctx(headers: Record<string, string> = {}): Context {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return { req: { header: (name: string) => lower[name.toLowerCase()] } } as unknown as Context;
}

describe("getClientIp", () => {
  beforeEach(() => {
    mockEnv.TRUST_PROXY = "true";
    mockEnv.TRUST_PROXY_HOP_COUNT = 1;
    mockGetConnInfo.mockReset();
    mockGetConnInfo.mockReturnValue({ remote: { address: "10.0.0.5" } });
  });

  it("returns the single XFF entry with one proxy hop", () => {
    expect(getClientIp(ctx({ "x-forwarded-for": "1.2.3.4" }))).toBe("1.2.3.4");
  });

  it("ignores a spoofed leftmost XFF entry and takes the proxy-appended one", () => {
    // Attacker prepends "9.9.9.9"; the trusted proxy appends the real peer.
    expect(getClientIp(ctx({ "x-forwarded-for": "9.9.9.9, 5.6.7.8" }))).toBe("5.6.7.8");
  });

  it("honours a multi-hop trusted-proxy count", () => {
    mockEnv.TRUST_PROXY_HOP_COUNT = 2;
    expect(getClientIp(ctx({ "x-forwarded-for": "realclient, proxy1" }))).toBe("realclient");
  });

  it("clamps when the header is shorter than the hop count", () => {
    mockEnv.TRUST_PROXY_HOP_COUNT = 3;
    expect(getClientIp(ctx({ "x-forwarded-for": "1.1.1.1" }))).toBe("1.1.1.1");
  });

  it("falls back to x-real-ip when XFF is absent", () => {
    expect(getClientIp(ctx({ "x-real-ip": "8.8.8.8" }))).toBe("8.8.8.8");
  });

  it("uses the socket peer address when TRUST_PROXY is false (ignores spoofed XFF)", () => {
    mockEnv.TRUST_PROXY = "false";
    expect(getClientIp(ctx({ "x-forwarded-for": "9.9.9.9" }))).toBe("10.0.0.5");
  });

  it("returns 'unknown' only when no source is available", () => {
    mockEnv.TRUST_PROXY = "false";
    mockGetConnInfo.mockImplementation(() => {
      throw new Error("no conn info");
    });
    expect(getClientIp(ctx({}))).toBe("unknown");
  });

  it("ignores XFF when the peer is a public address", () => {
    mockGetConnInfo.mockReturnValue({ remote: { address: "203.0.113.5" } });
    expect(getClientIp(ctx({ "x-forwarded-for": "9.9.9.9" }))).toBe("203.0.113.5");
  });

  it("ignores x-real-ip when the peer is a public address and XFF is absent", () => {
    mockGetConnInfo.mockReturnValue({ remote: { address: "203.0.113.5" } });
    expect(getClientIp(ctx({ "x-real-ip": "8.8.8.8" }))).toBe("203.0.113.5");
  });

  it("trusts XFF when the peer is an IPv4-mapped private address", () => {
    mockGetConnInfo.mockReturnValue({ remote: { address: "::ffff:10.0.0.5" } });
    expect(getClientIp(ctx({ "x-forwarded-for": "1.2.3.4" }))).toBe("1.2.3.4");
  });

  it("returns 'unknown' when the peer cannot be determined, even if XFF is set", () => {
    mockGetConnInfo.mockImplementation(() => {
      throw new Error("no conn info");
    });
    expect(getClientIp(ctx({ "x-forwarded-for": "1.2.3.4" }))).toBe("unknown");
  });

  it("returns 'unknown' when the socket has no address, even if XFF is set", () => {
    mockGetConnInfo.mockReturnValue({ remote: {} });
    expect(getClientIp(ctx({ "x-forwarded-for": "1.2.3.4" }))).toBe("unknown");
  });
});
