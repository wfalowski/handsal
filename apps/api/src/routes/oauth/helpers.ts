/** application/x-www-form-urlencoded decode (RFC 6749 Appendix B); null on malformed percent-encoding. */
function formUrlDecode(value: string): string | null {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return null;
  }
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Parse `Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))`
 * (RFC 6749 §2.3.1). Returns null for anything malformed or with an empty part.
 */
export function parseBasicAuth(
  authHeader: string | undefined,
): { clientId: string; clientSecret: string } | null {
  const match = authHeader?.match(/^Basic +(\S+)$/i);
  if (!match || !BASE64_RE.test(match[1])) return null;

  const decoded = Buffer.from(match[1], "base64").toString("utf8");
  const colonIndex = decoded.indexOf(":");
  if (colonIndex === -1) return null;

  const clientId = formUrlDecode(decoded.slice(0, colonIndex));
  const clientSecret = formUrlDecode(decoded.slice(colonIndex + 1));
  if (!clientId || !clientSecret) return null;

  return { clientId, clientSecret };
}

export function isFormUrlEncoded(contentType: string | undefined): boolean {
  if (!contentType) return false;
  return contentType.split(";")[0].trim().toLowerCase() === "application/x-www-form-urlencoded";
}
