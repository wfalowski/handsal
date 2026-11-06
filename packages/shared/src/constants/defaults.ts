export const DEFAULTS = {
  TOKEN_TTL_SECONDS: 3600,
  TTL_MIN: 60,
  TTL_MAX: 86400,
  SECRET_GRACE_SECONDS: 86400,
  TOKEN_EVENTS_RETENTION_DAYS: 30,
  TOKEN_EVENTS_PAGE_SIZE: 50,
} as const;

// Agent guardrails (Task 6.2). TTL options are UI presets only; the backend TTL range is unchanged.
export const AGENT_TTL_OPTIONS = [60, 300, 900] as const;
export const AGENT_MAX_SCOPES_MIN = 1;
export const AGENT_MAX_SCOPES_MAX = 50;
export const AGENT_BUDGET_MIN = 1;
export const AGENT_BUDGET_MAX = 100000;
export const AGENT_CIDRS_MAX = 20;
