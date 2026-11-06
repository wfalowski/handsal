import type { MeUser } from "./types";

// In-memory only: GET /api/auth/me returns the CSRF token again after a reload.
let session: { user: MeUser; csrfToken: string } | null = null;

export function setSession(next: { user: MeUser; csrfToken: string }): void {
  session = next;
}

export function clearSession(): void {
  session = null;
}

export function getCsrfToken(): string | null {
  return session?.csrfToken ?? null;
}
