import type { Hono } from "hono";

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
