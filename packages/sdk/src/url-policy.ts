/** Opt-outs shared by the verifier and the client. Both default to off. */
export interface UrlPolicyOptions {
  allowInsecureHttp?: boolean;
  allowCrossOrigin?: boolean;
}

/** Brackets and a trailing dot removed, lowercased. */
function bareHost(hostname: string): string {
  return hostname
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

/** `localhost`, `*.localhost`, a dotted-quad `127.0.0.0/8` literal, or `::1`. Nothing else. */
export function isLoopback(hostname: string): boolean {
  const host = bareHost(hostname);
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
  const parts = host.split(".");
  return (
    parts.length === 4 &&
    parts[0] === "127" &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  );
}

function origin(url: URL): [string, string] {
  return [bareHost(url.hostname), url.port || (url.protocol === "https:" ? "443" : "80")];
}

/**
 * Throws a plain `Error` naming `label` unless `value` is an absolute http(s) URL without
 * userinfo, on https or loopback (or `allowInsecureHttp`), and, when `issuer` is given, on the
 * same host and port as `issuer` (or `allowCrossOrigin`). Returns the parsed URL; callers keep
 * using their own string.
 */
export function checkUrl(
  label: string,
  value: string,
  options: UrlPolicyOptions,
  issuer?: URL,
): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Handsal ${label} is invalid`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`Handsal ${label} is invalid`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new Error(`Handsal ${label} is invalid: it must not contain a username or password`);
  }
  if (url.protocol === "http:" && options.allowInsecureHttp !== true && !isLoopback(url.hostname)) {
    throw new Error(
      `Handsal ${label} is invalid: it must use https (http is accepted for localhost or 127.0.0.0/8 only; set allowInsecureHttp to allow it)`,
    );
  }
  if (issuer && options.allowCrossOrigin !== true) {
    const [host, port] = origin(url);
    const [issuerHost, issuerPort] = origin(issuer);
    if (host !== issuerHost || port !== issuerPort) {
      throw new Error(
        `Handsal ${label} is invalid: its host and port (${host} ${port}) differ from issuer (${issuerHost} ${issuerPort}); set allowCrossOrigin to allow it`,
      );
    }
  }
  return url;
}
