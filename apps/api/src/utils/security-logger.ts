import type { Context } from "hono";
import { getClientIp } from "./client-ip.js";
import { rootLogger } from "./logger.js";

export const SecuritySeverity = {
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
} as const;

export type SecuritySeverityLevel = (typeof SecuritySeverity)[keyof typeof SecuritySeverity];

export const SecurityEvent = {
  // Auth failures
  CLIENT_AUTH_FAILURE: "client_auth_failure",
  CLIENT_AUTH_MALFORMED_ID: "client_auth_malformed_id",
  ADMIN_AUTH_FAILURE: "admin_auth_failure",
  ADMIN_LOGIN_FAILURE: "admin_login_failure",

  // Successful operations (audit trail)
  ADMIN_LOGIN_SUCCESS: "admin_login_success",
  ADMIN_LOGOUT: "admin_logout",
  TOKEN_ISSUED: "token_issued",
  TOKEN_REVOKED: "token_revoked",
  TOKEN_INTROSPECTED: "token_introspected",

  // Policy violations
  RATE_LIMIT_EXCEEDED: "rate_limit_exceeded",
  INVALID_SCOPE_REQUEST: "invalid_scope_request",
  UNAUTHORIZED_RESOURCE: "unauthorized_resource",
  UNSUPPORTED_GRANT_TYPE: "unsupported_grant_type",

  // Admin privileged operations
  CLIENT_CREATED: "client_created",
  CLIENT_DELETED: "client_deleted",
  CLIENT_SECRET_ROTATED: "client_secret_rotated",
  SCOPES_ASSIGNED: "scopes_assigned",
  RESOURCES_ASSIGNED: "resources_assigned",

  // Suspicious activity
  MALFORMED_REQUEST: "malformed_request",
  INACTIVE_TENANT_ACCESS: "inactive_tenant_access",
} as const;

export type SecurityEventType = (typeof SecurityEvent)[keyof typeof SecurityEvent];

const securityLogger = rootLogger.child({ module: "security", security: true });

interface SecurityLogPayload {
  event: SecurityEventType;
  severity: SecuritySeverityLevel;
  sourceIp?: string;
  tenantId?: string;
  clientId?: string;
  path?: string;
  method?: string;
  requestId?: string;
  details?: Record<string, unknown>;
}

// clientId often comes straight from an unauthenticated request; cap it so callers cannot bloat the log.
const MAX_CLIENT_ID_LOG_LENGTH = 128;

export function logSecurityEvent(payload: SecurityLogPayload): void {
  const { event, severity, ...rest } = payload;
  const logData = {
    event,
    severity,
    ...rest,
    clientId: rest.clientId?.slice(0, MAX_CLIENT_ID_LOG_LENGTH),
  };

  switch (severity) {
    case SecuritySeverity.CRITICAL:
      securityLogger.fatal(logData, `[SECURITY] ${event}`);
      break;
    case SecuritySeverity.HIGH:
    case SecuritySeverity.MEDIUM:
      securityLogger.warn(logData, `[SECURITY] ${event}`);
      break;
    case SecuritySeverity.LOW:
      securityLogger.info(logData, `[SECURITY] ${event}`);
      break;
  }
}

export function extractRequestInfo(c: Context): {
  sourceIp: string;
  path: string;
  method: string;
  requestId?: string;
} {
  return {
    sourceIp: getClientIp(c),
    path: c.req.path,
    method: c.req.method,
    requestId: c.get("requestId") as string | undefined,
  };
}
