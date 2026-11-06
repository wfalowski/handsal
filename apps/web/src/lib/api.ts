import type { ApiErrorBody } from "@handsal/shared";
import { clearSession, getCsrfToken } from "./auth";

export class ApiRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly description: string,
    readonly details?: unknown,
  ) {
    super(description);
    this.name = "ApiRequestError";
  }
}

// These two handle 401 themselves (inline login error / route-guard redirect).
const HANDLES_OWN_401 = new Set(["/api/auth/login", "/api/auth/me"]);

export async function api<T>(
  path: string,
  init: Omit<RequestInit, "body"> & { body?: unknown } = {},
): Promise<T> {
  const { body, headers, ...rest } = init;
  const outHeaders = new Headers(headers);
  if (body !== undefined) outHeaders.set("Content-Type", "application/json");
  const csrf = getCsrfToken();
  if (csrf) outHeaders.set("X-CSRF-Token", csrf);

  const res = await fetch(path, {
    ...rest,
    headers: outHeaders,
    credentials: "include",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (!res.ok) {
    const err: Partial<ApiErrorBody> = await res.json().catch(() => ({}));
    if (res.status === 401 && !HANDLES_OWN_401.has(path)) {
      clearSession();
      if (window.location.pathname !== "/login") window.location.assign("/login");
    }
    throw new ApiRequestError(
      res.status,
      err.error ?? "unknown_error",
      err.error_description ?? res.statusText,
      err.details,
    );
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}
