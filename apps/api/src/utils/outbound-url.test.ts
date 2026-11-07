import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { env } from "../env.js";
import {
  type AddressLookup,
  createPinnedAgent,
  isInternalAddress,
  OutboundUrlError,
  pinnedConnectLookup,
  pinnedFetch,
  resolveOutboundUrl,
  setOutboundLookupForTests,
} from "./outbound-url.js";

const publicAnswer: AddressLookup = async () => [{ address: "192.0.2.1", family: 4 }];

afterEach(() => {
  env.NODE_ENV = "test";
  setOutboundLookupForTests(null);
});

describe("isInternalAddress", () => {
  it("matches loopback, link-local, RFC1918, CGNAT, ULA and unspecified", () => {
    for (const ip of [
      "127.0.0.1",
      "10.1.2.3",
      "192.168.1.1",
      "172.16.0.1",
      "169.254.169.254",
      "100.64.0.1",
      "100.127.255.255",
      "0.0.0.1",
      "::1",
      "::",
      "fe80::1",
      "fd00::1",
      "fc00::1",
      "::ffff:192.168.1.1",
      "::ffff:c0a8:101",
      "::ffff:127.0.0.1",
    ]) {
      expect(isInternalAddress(ip), ip).toBe(true);
    }
    for (const ip of ["8.8.8.8", "100.128.0.1", "172.32.0.1", "192.0.2.1", "2001:db8::1"]) {
      expect(isInternalAddress(ip), ip).toBe(false);
    }
  });
});

describe("resolveOutboundUrl", () => {
  it("allows http and internal hosts outside production and does not resolve", async () => {
    const lookup = vi.fn(publicAnswer);
    const resolved = await resolveOutboundUrl("http://127.0.0.1:8080/hook", lookup);
    expect(resolved.url.hostname).toBe("127.0.0.1");
    expect(resolved.addresses).toEqual([]);
    expect(lookup).not.toHaveBeenCalled();
    await expect(resolveOutboundUrl("ftp://hooks.example.com/x", lookup)).rejects.toMatchObject({
      code: "protocol",
    });
  });

  it("rejects non-https, literals, blocked names and rebinding answers in production", async () => {
    env.NODE_ENV = "production";
    const lookup = vi.fn(publicAnswer);
    await expect(resolveOutboundUrl("http://hooks.example.com/x", lookup)).rejects.toBeInstanceOf(
      OutboundUrlError,
    );
    await expect(resolveOutboundUrl("http://hooks.example.com/x", lookup)).rejects.toMatchObject({
      code: "protocol",
    });

    for (const url of [
      "https://10.0.0.1/",
      "https://[::1]/jwks",
      "https://[::ffff:192.168.1.1]/jwks",
      "https://169.254.169.254/latest",
      "https://100.64.1.1/",
      "https://2130706433/",
      "https://0x7f000001/",
      "https://metadata.google.internal/",
      "https://localhost/hook",
      "https://printer.local/hook",
      "https://app.localhost/hook",
      "https://[fd12::1]/hook",
    ]) {
      await expect(resolveOutboundUrl(url, lookup), url).rejects.toMatchObject({
        code: "internal",
      });
    }
    expect(lookup).not.toHaveBeenCalled();

    const ok = await resolveOutboundUrl("https://hooks.example.com/x", lookup);
    expect(ok.addresses).toEqual([{ address: "192.0.2.1", family: 4 }]);
    expect(lookup).toHaveBeenCalledWith("hooks.example.com");

    lookup.mockResolvedValueOnce([
      { address: "192.0.2.1", family: 4 },
      { address: "169.254.169.254", family: 4 },
    ]);
    await expect(resolveOutboundUrl("https://both.example/jwks", lookup)).rejects.toMatchObject({
      code: "internal",
    });

    lookup.mockRejectedValueOnce(new Error("ENOTFOUND"));
    await expect(resolveOutboundUrl("https://missing.example/jwks", lookup)).rejects.toMatchObject({
      code: "lookup",
    });
  });
});

describe("pinnedConnectLookup", () => {
  it("returns only the pinned address for both lookup callback shapes", () => {
    const lookup = pinnedConnectLookup({ address: "192.0.2.1", family: 4 });
    const seen: unknown[] = [];
    lookup("rebinding.example", { all: true }, (_err, addresses) => seen.push(addresses));
    lookup("rebinding.example", {}, (_err, address, family) => seen.push([address, family]));
    expect(seen).toEqual([[{ address: "192.0.2.1", family: 4 }], ["192.0.2.1", 4]]);
  });
});

describe("pinnedFetch", () => {
  it("does not follow redirects outside production", async () => {
    const server = createServer((req, res) => {
      if (req.url === "/secret") {
        res.end("followed");
        return;
      }
      res.writeHead(302, { location: "/secret" });
      res.end();
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const port = (server.address() as AddressInfo).port;
    try {
      const res = await pinnedFetch(`http://127.0.0.1:${port}/hook`, { redirect: "follow" });
      expect(res.status).toBe(302);
      await res.body?.cancel();
    } finally {
      server.close();
    }
  });

  it("connects to the pinned address rather than the hostname", async () => {
    let host = "";
    const server = createServer((req, res) => {
      host = req.headers.host ?? "";
      res.end("pinned-ok");
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const port = (server.address() as AddressInfo).port;
    const agent = await createPinnedAgent({ address: "127.0.0.1", family: 4 });
    try {
      const res = await fetch(`http://not-a-real-host.invalid:${port}/`, {
        dispatcher: agent,
        redirect: "manual",
      } as RequestInit);
      expect(await res.text()).toBe("pinned-ok");
      expect(host).toBe(`not-a-real-host.invalid:${port}`);
    } finally {
      await agent.close();
      server.close();
    }
  });

  it("refuses a name that resolves to an internal address before connecting", async () => {
    env.NODE_ENV = "production";
    setOutboundLookupForTests(async () => [{ address: "169.254.169.254", family: 4 }]);
    await expect(pinnedFetch("https://169.254.169.254.nip.io/latest")).rejects.toMatchObject({
      code: "internal",
    });
  });
});
