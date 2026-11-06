export const DEFAULTS = {
  TOKEN_TTL_SECONDS: 3600,
  TTL_MIN: 60,
  TTL_MAX: 86400,
  SECRET_GRACE_SECONDS: 86400,
  TOKEN_EVENTS_RETENTION_DAYS: 30,
  TOKEN_EVENTS_PAGE_SIZE: 50,
} as const;

export const SLUG_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const SCOPE_NAME_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/;
export const CLIENT_ID_REGEX = /^app_[a-z2-7]{20}$/;
