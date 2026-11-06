export const GRANT_TYPES = {
  CLIENT_CREDENTIALS: "client_credentials",
  APPROVAL: "urn:handsal:params:grant-type:approval",
  TOKEN_EXCHANGE: "urn:ietf:params:oauth:grant-type:token-exchange",
} as const;
export const TOKEN_TYPES = { BEARER: "Bearer" } as const;
// RFC 8693 token type identifiers (subject_token_type, issued_token_type).
export const TOKEN_TYPE_URNS = {
  ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
  JWT: "urn:ietf:params:oauth:token-type:jwt",
} as const;
export type TokenTypeUrn = (typeof TOKEN_TYPE_URNS)[keyof typeof TOKEN_TYPE_URNS];
// Exchanged tokens are always Handsal access tokens.
export const ISSUED_TOKEN_TYPE = TOKEN_TYPE_URNS.ACCESS_TOKEN;
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
  AUTHORIZATION_PENDING: "authorization_pending",
  ACCESS_DENIED: "access_denied",
  EXPIRED_TOKEN: "expired_token",
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
  PENDING: "pending",
} as const;
export type TokenEventOutcome = (typeof TOKEN_EVENT_OUTCOMES)[keyof typeof TOKEN_EVENT_OUTCOMES];

export const APPROVAL_STATUSES = {
  PENDING: "pending",
  APPROVED: "approved",
  DENIED: "denied",
  EXPIRED: "expired",
} as const;
export type ApprovalStatus = (typeof APPROVAL_STATUSES)[keyof typeof APPROVAL_STATUSES];

export const MAY_ACT_FOR = { USERS: "users", TENANT: "tenant", SERVICES: "services" } as const;
export type MayActFor = (typeof MAY_ACT_FOR)[keyof typeof MAY_ACT_FOR];

export const DELEGATION_SCOPE_MODES = {
  INTERSECTION: "intersection",
  AGENT_ONLY: "agent_only",
} as const;
export type DelegationScopeMode =
  (typeof DELEGATION_SCOPE_MODES)[keyof typeof DELEGATION_SCOPE_MODES];
