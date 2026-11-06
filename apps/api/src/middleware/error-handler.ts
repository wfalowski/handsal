import { OAUTH_ERRORS } from "@handsal/shared";
import type { Context } from "hono";
import { HTTPException } from "hono/http-exception";
import { ZodError, z } from "zod";
import { createLogger } from "../utils/logger.js";
import {
  extractRequestInfo,
  logSecurityEvent,
  SecurityEvent,
  SecuritySeverity,
} from "../utils/security-logger.js";

const logger = createLogger("error-handler");

/** RFC 6749 §5.2 error, thrown from OAuth routes (`/t/:slug/...`). */
export class OAuthError extends Error {
  public securityLogged = false;
  /** Internal failure reason for token events/logs (e.g. `bad_secret`); never sent to the client. */
  public reason?: string;

  constructor(
    public readonly errorCode: string,
    public readonly statusCode: number,
    public readonly errorDescription?: string,
  ) {
    super(errorDescription ?? errorCode);
    this.name = "OAuthError";
  }
}

/** Management API error (`/api/...`): `{ error, error_description, details? }`. */
export class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly errorCode: string,
    public readonly errorDescription: string,
    public readonly details?: unknown,
  ) {
    super(errorDescription);
    this.name = "ApiError";
  }
}

const SECURITY_ERROR_CODES = new Set<string>([
  OAUTH_ERRORS.INVALID_CLIENT,
  OAUTH_ERRORS.INVALID_SCOPE,
  OAUTH_ERRORS.UNAUTHORIZED_CLIENT,
  OAUTH_ERRORS.UNSUPPORTED_GRANT_TYPE,
]);

export function errorHandler(err: Error, c: Context): Response {
  if (err instanceof OAuthError) {
    if (!err.securityLogged && SECURITY_ERROR_CODES.has(err.errorCode)) {
      logSecurityEvent({
        ...extractRequestInfo(c),
        event: SecurityEvent.MALFORMED_REQUEST,
        severity: SecuritySeverity.MEDIUM,
        details: { errorCode: err.errorCode, errorDescription: err.errorDescription },
      });
    }

    // RFC 6749 §5.2: when client authentication fails, include WWW-Authenticate
    if (err.statusCode === 401 && err.errorCode === OAUTH_ERRORS.INVALID_CLIENT) {
      c.header("WWW-Authenticate", 'Basic realm="oauth"');
    }
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    return c.json(
      { error: err.errorCode, error_description: err.errorDescription },
      err.statusCode as 400,
    );
  }

  if (err instanceof ApiError) {
    return c.json(
      {
        error: err.errorCode,
        error_description: err.errorDescription,
        ...(err.details !== undefined && { details: err.details }),
      },
      err.statusCode as 400,
    );
  }

  if (err instanceof ZodError) {
    return c.json(
      {
        error: "validation_error",
        error_description: "Request validation failed",
        details: z.flattenError(err),
      },
      400,
    );
  }

  if (err instanceof HTTPException) {
    return err.getResponse();
  }

  logger.error({ err, requestId: c.get("requestId") }, "Unhandled error");
  return c.json(
    { error: OAUTH_ERRORS.SERVER_ERROR, error_description: "An unexpected error occurred" },
    500,
  );
}
