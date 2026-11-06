import { BlockList, isIPv4, isIPv6 } from "node:net";

type Family = "ipv4" | "ipv6";

const familyOf = (ip: string): Family | null => (isIPv4(ip) ? "ipv4" : isIPv6(ip) ? "ipv6" : null);
// `::ffff:a.b.c.d` is an IPv4 client on a dual-stack socket; match it against IPv4 ranges.
const unmapIPv4 = (ip: string) => ip.replace(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i, "$1");

/** Parses CIDRs with Node's own parser. Throws on a malformed entry. */
export function parseCidrs(cidrs: string[]): BlockList {
  const list = new BlockList();
  for (const cidr of cidrs) {
    const [addr, prefix, extra] = cidr.split("/");
    const family = familyOf(addr);
    if (!family || extra !== undefined || !/^\d{1,3}$/.test(prefix ?? "")) {
      throw new Error(`Invalid CIDR: ${cidr}`);
    }
    list.addSubnet(addr, Number(prefix), family); // RangeError on an out-of-range prefix
  }
  return list;
}

/** True when `ip` is in any of `cidrs`; `cidrs` empty means unrestricted. Throws on a malformed entry. */
export function ipInCidrs(ip: string, cidrs: string[]): boolean {
  if (cidrs.length === 0) return true;
  const list = parseCidrs(cidrs);
  const addr = unmapIPv4(ip);
  const family = familyOf(addr);
  return family !== null && list.check(addr, family);
}
