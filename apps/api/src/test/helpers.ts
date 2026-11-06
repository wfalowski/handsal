import type { Hono } from "hono";
import { loginRateLimitStore } from "../routes/management/auth.js";

type RequestableApp = Pick<Hono<any>, "request">;

/** Send a JSON request (body is JSON-encoded when given). */
export async function jsonRequest(
  app: RequestableApp,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  return app.request(path, {
    method,
    headers: body === undefined ? headers : { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** POST an `application/x-www-form-urlencoded` body (the OAuth endpoints' format). */
export async function formRequest(
  app: RequestableApp,
  path: string,
  fields: Record<string, string>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(fields).toString(),
  });
}

/** Log in via `POST /api/auth/login`; returns the `Cookie` header value and the CSRF token. */
export async function loginAs(
  app: RequestableApp,
  email: string,
  password: string,
): Promise<{ cookie: string; csrf: string }> {
  // All test requests share one IP bucket; reset the 5/15min login limiter so suites can log in freely.
  await loginRateLimitStore.clear();
  const res = await jsonRequest(app, "POST", "/api/auth/login", { email, password });
  if (res.status !== 200) throw new Error(`loginAs(${email}) failed with ${res.status}`);
  const { csrfToken } = (await res.json()) as { csrfToken: string };
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0];
  return { cookie, csrf: csrfToken };
}
