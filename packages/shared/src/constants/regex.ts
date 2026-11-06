// Zod-free so the web can import them via `@handsal/shared/constants` without pulling zod into its chunks.
export const SLUG_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const SCOPE_NAME_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/;
export const CLIENT_ID_REGEX = /^app_[a-z2-7]{20}$/;
