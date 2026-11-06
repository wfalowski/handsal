// Zod-free so the web can import them via `@handsal/shared/constants` without pulling zod into its chunks.
export const SLUG_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const SCOPE_NAME_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/;
export const CLIENT_ID_REGEX = /^app_[a-z2-7]{20}$/;
// Loose shape check only; the server validates CIDRs authoritatively with node:net.
export const CIDR_REGEX =
  /^(?:\d{1,3}(?:\.\d{1,3}){3}\/(?:3[0-2]|[12]?\d)|[0-9A-Fa-f:]{2,45}\/(?:12[0-8]|1[01]\d|[1-9]?\d))$/;
// No whitespace or control characters: safe in logs, URLs and the UI without escaping.
export const TASK_ID_REGEX = /^[A-Za-z0-9._:-]{1,128}$/;
