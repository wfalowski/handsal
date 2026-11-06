import type { MeUser } from "./types";

// The CSRF token is not part of GET /api/auth/me, so it is mirrored in sessionStorage to
// survive a page reload (it is bound to the session cookie and useless without it).
const CSRF_KEY = "handsal.csrf";

let session: { user: MeUser; csrfToken: string } | null = null;

export function setSession(next: { user: MeUser; csrfToken: string }): void {
  session = next;
  try {
    sessionStorage.setItem(CSRF_KEY, next.csrfToken);
  } catch {
    // storage unavailable: the token stays in memory only
  }
}

export function clearSession(): void {
  session = null;
  try {
    sessionStorage.removeItem(CSRF_KEY);
  } catch {
    // ignore
  }
}

export function getCsrfToken(): string | null {
  if (session) return session.csrfToken;
  try {
    return sessionStorage.getItem(CSRF_KEY);
  } catch {
    return null;
  }
}
