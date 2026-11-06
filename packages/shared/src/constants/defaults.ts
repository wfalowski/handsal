export const DEFAULTS = {
  TOKEN_TTL_SECONDS: 3600,
  TTL_MIN: 60,
  TTL_MAX: 86400,
  SECRET_GRACE_SECONDS: 86400,
  TOKEN_EVENTS_RETENTION_DAYS: 30,
  TOKEN_EVENTS_PAGE_SIZE: 50,
  // Scope ceiling with human approval (Task 6.3).
  APPROVAL_TTL_SECONDS: 1800,
  APPROVAL_TOKEN_TTL_SECONDS: 300,
  APPROVAL_POLL_INTERVAL_SECONDS: 5,
  APPROVALS_PAGE_SIZE: 50,
  // A rule-approved request polls immediately.
  APPROVAL_RULE_POLL_INTERVAL_SECONDS: 0,
  // Live pending approvals one application may hold; resolved rows are purged after this many days.
  APPROVAL_MAX_PENDING_PER_APPLICATION: 20,
  APPROVAL_RETENTION_DAYS: 30,
} as const;

// Approval notification webhook (Task 6.5): one retry on network error or 5xx, never on 4xx.
export const APPROVAL_WEBHOOK = {
  EVENT_PENDING: "approval.pending",
  SIGNATURE_HEADER: "X-Handsal-Signature",
  EVENT_HEADER: "X-Handsal-Event",
  TIMEOUT_MS: 5000,
  RETRY_DELAY_MS: 2000,
  SLACK_HOST_SUFFIX: "hooks.slack.com",
} as const;

// Agent guardrails (Task 6.2). TTL options are UI presets only; the backend TTL range is unchanged.
export const AGENT_TTL_OPTIONS = [60, 300, 900] as const;
export const AGENT_MAX_SCOPES_MIN = 1;
export const AGENT_MAX_SCOPES_MAX = 50;
export const AGENT_BUDGET_MIN = 1;
export const AGENT_BUDGET_MAX = 100000;
export const AGENT_CIDRS_MAX = 20;
