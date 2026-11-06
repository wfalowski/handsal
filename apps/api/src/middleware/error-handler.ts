import { OAUTH_ERRORS } from "@handsal/shared";
import type { Context } from "hono";
import { HTTPException } from "hono/http-exception";
import { ZodError, z } from "zod";
import { createLogger } from "../utils/logger.js";
import {
  extractRequestInfo,
  logSecurityEvent,
  SecurityEvent,
  type SecurityEventType,
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

// OAuth error code -> security event logged for it (unless already logged at source).
const SECURITY_ERROR_EVENTS = new Map<string, SecurityEventType>([
  [OAUTH_ERRORS.INVALID_CLIENT, SecurityEvent.CLIENT_AUTH_FAILURE],
  [OAUTH_ERRORS.INVALID_SCOPE, SecurityEvent.INVALID_SCOPE_REQUEST],
  [OAUTH_ERRORS.UNAUTHORIZED_CLIENT, SecurityEvent.MALFORMED_REQUEST],
  [OAUTH_ERRORS.UNSUPPORTED_GRANT_TYPE, SecurityEvent.MALFORMED_REQUEST],
]);

export function errorHandler(err: Error, c: Context): Response {
  if (err instanceof OAuthError) {
    const event = SECURITY_ERROR_EVENTS.get(err.errorCode);
    if (!err.securityLogged && event) {
      logSecurityEvent({
        ...extractRequestInfo(c),
        event,
        severity: SecuritySeverity.MEDIUM,
        details: { errorCode: err.errorCode, errorDescription: err.errorDescription },
      });
    }

    // RFC 6749 §5.2: when client authentication fails, include WWW-Authenticate
    if (err.statusCode === 401 && err.errorCode === OAUTH_ERRORS.INVALID_CLIENT) {
      c.header("WWW-Authenticate", 'Basic realm="handsal"');
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
