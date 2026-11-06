import { decodeJwt } from "jose";

/** `iss` of an unverified client assertion when it is a string equal to `sub` (the claimed client_id). */
export function assertionClientId(assertion: string | undefined): string | undefined {
  if (!assertion) return undefined;
  try {
    const { iss, sub } = decodeJwt(assertion);
    return typeof iss === "string" && typeof sub === "string" && iss && iss === sub
      ? iss
      : undefined;
  } catch {
    return undefined;
  }
}
