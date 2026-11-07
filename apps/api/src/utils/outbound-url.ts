import { lookup as dnsLookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { env } from "../env.js";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/** `dns.lookup(host, { all: true, verbatim: true })` shape, injectable in tests. */
export type AddressLookup = (host: string) => Promise<ResolvedAddress[]>;

export class OutboundUrlError extends Error {
  constructor(readonly code: "protocol" | "internal" | "lookup") {
    super(code);
    this.name = "OutboundUrlError";
  }
}

// Loopback, link-local, RFC 1918, CGNAT, and unique-local ranges.
// IPv4-mapped IPv6 (`::ffff:a.b.c.d` and the hex form WHATWG emits) is checked as ipv6;
// Node's BlockList applies the IPv4 ranges to those addresses.
const internalNets = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
] as const) {
  internalNets.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["fe80::", 10],
  ["fc00::", 7],
] as const) {
  internalNets.addSubnet(net, prefix, "ipv6");
}

const bareHost = (hostname: string) =>
  hostname
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase();

/** True for a literal IP in an internal range. Unparseable strings fail closed. */
export function isInternalAddress(address: string): boolean {
  const host = bareHost(address);
  const family = isIP(host);
  if (family === 0) return true;
  return internalNets.check(host, family === 4 ? "ipv4" : "ipv6");
}

function isBlockedName(hostname: string): boolean {
  const host = bareHost(hostname);
  if (isIP(host) !== 0) return false;
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".internal") ||
    host.endsWith(".local")
  );
}

export const realDnsLookup: AddressLookup = async (host) => {
  const rows = await dnsLookup(host, { all: true, verbatim: true });
  return rows.map((row) => ({
    address: row.address,
    family: row.family === 6 ? 6 : 4,
  }));
};

let lookupImpl: AddressLookup = realDnsLookup;

/** Tests replace DNS so production URL checks never touch the network. `null` restores it. */
export function setOutboundLookupForTests(lookup: AddressLookup | null): void {
  lookupImpl = lookup ?? realDnsLookup;
}

export interface ResolvedOutbound {
  url: URL;
  /** Empty outside production (no pin). In production, public addresses only. */
  addresses: ResolvedAddress[];
}

/**
 * Production: https only, no internal name or literal, and every DNS answer must be public
 * (one internal address fails closed). Other environments: http or https, no resolution,
 * internal hosts allowed (local webhooks and IdPs).
 */
export async function resolveOutboundUrl(
  raw: string,
  lookup: AddressLookup = lookupImpl,
): Promise<ResolvedOutbound> {
  const url = new URL(raw);
  const production = env.NODE_ENV === "production";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && !production)) {
    throw new OutboundUrlError("protocol");
  }
  if (!production) return { url, addresses: [] };

  const host = bareHost(url.hostname);
  if (isBlockedName(host) || (isIP(host) !== 0 && isInternalAddress(host))) {
    throw new OutboundUrlError("internal");
  }
  // Literals cannot rebind. WHATWG already normalised integer/hex/octal spellings.
  if (isIP(host) !== 0) {
    return { url, addresses: [{ address: host, family: isIP(host) === 6 ? 6 : 4 }] };
  }

  let rows: ResolvedAddress[];
  try {
    rows = await lookup(host);
  } catch {
    throw new OutboundUrlError("lookup");
  }
  if (rows.length === 0) throw new OutboundUrlError("lookup");
  const addresses: ResolvedAddress[] = [];
  for (const row of rows) {
    // Trust the address string, not the caller's family: a mapped or garbage answer fails closed.
    const address = bareHost(row.address);
    const family = isIP(address);
    if ((family !== 4 && family !== 6) || isInternalAddress(address)) {
      throw new OutboundUrlError("internal");
    }
    addresses.push({ address, family });
  }
  return { url, addresses };
}

/** undici `connect.lookup` that returns only the address resolved before the connect. */
export function pinnedConnectLookup(pinned: ResolvedAddress) {
  const record = { address: pinned.address, family: pinned.family };
  return (
    _hostname: string,
    options: { all?: boolean },
    callback: (
      err: Error | null,
      address: string | Array<{ address: string; family: number }>,
      family?: number,
    ) => void,
  ) => {
    if (options.all) callback(null, [record]);
    else callback(null, record.address, record.family);
  };
}

// Node bundles undici for fetch but does not export it. The process dispatcher is an Agent
// of that same build, so `connect.lookup` matches this process's fetch.
const UNDICI_DISPATCHER = Symbol.for("undici.globalDispatcher.2");

interface PinnedAgent {
  close(): Promise<void>;
}

interface PinnedAgentConstructor {
  new (options: {
    allowH2: false;
    connect: { lookup: ReturnType<typeof pinnedConnectLookup> };
  }): PinnedAgent;
  readonly name: string;
}

let agentConstructor: PinnedAgentConstructor | undefined;

async function undiciAgent(): Promise<PinnedAgentConstructor> {
  const read = () => {
    const box = globalThis as unknown as Record<
      symbol,
      { constructor?: PinnedAgentConstructor } | undefined
    >;
    return box[UNDICI_DISPATCHER]?.constructor;
  };
  if (!agentConstructor) agentConstructor = read();
  if (!agentConstructor) {
    await fetch("data:text/plain,");
    agentConstructor = read();
  }
  if (agentConstructor?.name !== "Agent") {
    throw new Error("undici Agent is not available");
  }
  return agentConstructor;
}

export async function createPinnedAgent(pinned: ResolvedAddress): Promise<PinnedAgent> {
  const Agent = await undiciAgent();
  // allowH2 off: undici 8's HTTP/2 connector ignores a custom connect.lookup.
  return new Agent({ allowH2: false, connect: { lookup: pinnedConnectLookup(pinned) } });
}

type FetchInit = RequestInit & { dispatcher?: unknown };

const NULL_BODY_STATUS = new Set([101, 204, 205, 304]);

function safeRedirect(redirect: RequestRedirect | undefined): "error" | "manual" {
  return redirect === "error" ? "error" : "manual";
}

/** Close the pin agent once the body is consumed or cancelled. */
function tieAgent(response: Response, agent: PinnedAgent): Response {
  const close = () => {
    void agent.close().catch(() => {});
  };
  const body = response.body;
  if (!body || NULL_BODY_STATUS.has(response.status)) {
    void body?.cancel().catch(() => {});
    close();
    return new Response(null, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }
  let closed = false;
  const closeOnce = () => {
    if (closed) return;
    closed = true;
    close();
  };
  const reader = body.getReader();
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          closeOnce();
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (err) {
        closeOnce();
        controller.error(err);
      }
    },
    async cancel(reason) {
      await reader.cancel(reason).catch(() => {});
      closeOnce();
    },
  });
  return new Response(stream, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

/**
 * Production: resolve once, refuse any internal address, fetch through an undici Agent pinned
 * to that address (no second lookup). Elsewhere: ordinary fetch, so dev webhooks to localhost
 * still work. Redirects are never followed.
 */
export async function pinnedFetch(url: string | URL, init?: FetchInit): Promise<Response> {
  const href = typeof url === "string" ? url : url.href;
  const redirect = safeRedirect(init?.redirect);
  const { dispatcher: _dispatcher, ...rest } = init ?? {};
  if (env.NODE_ENV !== "production") {
    return fetch(href, { ...rest, redirect });
  }
  const { url: target, addresses } = await resolveOutboundUrl(href);
  const pinned = addresses[0];
  if (!pinned) throw new OutboundUrlError("lookup");
  const agent = await createPinnedAgent(pinned);
  try {
    // Node's fetch accepts undici's `dispatcher`; the DOM RequestInit type does not.
    const response = await fetch(target, {
      ...rest,
      redirect,
      dispatcher: agent,
    } as RequestInit);
    return tieAgent(response, agent);
  } catch (err) {
    await agent.close().catch(() => {});
    throw err;
  }
}
