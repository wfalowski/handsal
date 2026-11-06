import { describe, expect, it } from "vitest";
import { ipInCidrs, parseCidrs } from "./cidr.js";

describe("ipInCidrs", () => {
  it("empty list allows any address", () => {
    expect(ipInCidrs("203.0.113.7", [])).toBe(true);
    expect(ipInCidrs("unknown", [])).toBe(true);
  });

  it("matches IPv4 ranges", () => {
    expect(ipInCidrs("10.40.0.5", ["10.40.0.0/16"])).toBe(true);
    expect(ipInCidrs("10.41.0.5", ["10.40.0.0/16"])).toBe(false);
    expect(ipInCidrs("10.41.0.5", ["192.168.0.0/24", "10.41.0.5/32"])).toBe(true);
  });

  it("matches IPv6 ranges", () => {
    expect(ipInCidrs("2001:db8::1", ["2001:db8::/32"])).toBe(true);
    expect(ipInCidrs("2001:db9::1", ["2001:db8::/32"])).toBe(false);
  });

  it("normalises IPv4-mapped IPv6 addresses", () => {
    expect(ipInCidrs("::ffff:10.40.0.5", ["10.40.0.0/16"])).toBe(true);
    expect(ipInCidrs("::FFFF:10.41.0.5", ["10.40.0.0/16"])).toBe(false);
  });

  it("an unparseable source address is not allowed", () => {
    expect(ipInCidrs("unknown", ["0.0.0.0/0"])).toBe(false);
  });

  it("throws on a malformed CIDR", () => {
    const bad = [
      "10.40.0.0",
      "10.40.0.0/33",
      "2001:db8::/129",
      "999.1.1.1/8",
      "a/b",
      "1.2.3.4/8/9",
    ];
    for (const cidr of bad) {
      expect(() => parseCidrs([cidr]), cidr).toThrow();
      expect(() => ipInCidrs("10.40.0.5", [cidr]), cidr).toThrow();
    }
  });
});
