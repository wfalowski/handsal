export const GRANT_TYPES = { CLIENT_CREDENTIALS: "client_credentials" } as const;
export const TOKEN_TYPES = { BEARER: "Bearer" } as const;
export const OAUTH_ERRORS = {
  INVALID_REQUEST: "invalid_request",
  INVALID_CLIENT: "invalid_client",
  INVALID_GRANT: "invalid_grant",
  UNAUTHORIZED_CLIENT: "unauthorized_client",
  UNSUPPORTED_GRANT_TYPE: "unsupported_grant_type",
  INVALID_SCOPE: "invalid_scope",
  INVALID_TARGET: "invalid_target",
  SERVER_ERROR: "server_error",
  TEMPORARILY_UNAVAILABLE: "temporarily_unavailable",
} as const;
export type OAuthErrorCode = (typeof OAUTH_ERRORS)[keyof typeof OAUTH_ERRORS];

export const CLIENT_ASSERTION_TYPES = {
  JWT_BEARER: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
} as const;
export const ASSERTION_MAX_LIFETIME_SECONDS = 300;
export const ASSERTION_CLOCK_TOLERANCE_SECONDS = 60;

export const TOKEN_ENDPOINT_AUTH_METHODS = {
  CLIENT_SECRET_BASIC: "client_secret_basic",
  CLIENT_SECRET_POST: "client_secret_post",
  PRIVATE_KEY_JWT: "private_key_jwt",
} as const;
export type TokenEndpointAuthMethod =
  (typeof TOKEN_ENDPOINT_AUTH_METHODS)[keyof typeof TOKEN_ENDPOINT_AUTH_METHODS];

export const APPLICATION_KINDS = { SERVICE: "service", AGENT: "agent" } as const;
export type ApplicationKind = (typeof APPLICATION_KINDS)[keyof typeof APPLICATION_KINDS];

export const RESOURCE_KINDS = { API: "api", MCP: "mcp" } as const;
export type ResourceKind = (typeof RESOURCE_KINDS)[keyof typeof RESOURCE_KINDS];

export const AGENT_POLICIES = { AUTO: "auto", APPROVAL: "approval", NEVER: "never" } as const;
export type AgentPolicy = (typeof AGENT_POLICIES)[keyof typeof AGENT_POLICIES];

export const TENANT_ROLES = { OWNER: "owner", ADMIN: "admin", AUDITOR: "auditor" } as const;
export type TenantRole = (typeof TENANT_ROLES)[keyof typeof TENANT_ROLES];

export const KEY_STATUSES = { ACTIVE: "active", RETIRING: "retiring", RETIRED: "retired" } as const;
export type KeyStatus = (typeof KEY_STATUSES)[keyof typeof KEY_STATUSES];

export const TOKEN_EVENT_OUTCOMES = {
  ISSUED: "issued",
  DENIED: "denied",
  REVOKED: "revoked",
} as const;
export type TokenEventOutcome = (typeof TOKEN_EVENT_OUTCOMES)[keyof typeof TOKEN_EVENT_OUTCOMES];
