import dotenv from "dotenv";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { z } from "zod";

// Load .env from the monorepo root (never overrides variables already set).
const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, "..", "..", "..", ".env"), quiet: true });

export const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATABASE_URL: z.string().min(1),
  // Base URL of this instance; tenant issuers are `${PUBLIC_URL}/t/<slug>`.
  PUBLIC_URL: z.url(),
  KEY_ENCRYPTION_SECRET: z
    .string()
    .length(64)
    .regex(/^[0-9a-f]{64}$/i, "Must be 64 hex characters (32 bytes)"),
  ADMIN_API_KEY: z.string().min(32, "ADMIN_API_KEY must be at least 32 characters").optional(),
  BOOTSTRAP_ADMIN_EMAIL: z.email().optional(),
  BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).optional(),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  CORS_ORIGINS: z.string().default("http://localhost:5173"),
  TRUST_PROXY: z.enum(["true", "false"]).default("false"),
  // Number of trusted reverse-proxy hops in front of the app. Used to pick the
  // real client IP from X-Forwarded-For counting from the right (only consulted
  // when TRUST_PROXY=true). Default 1 = a single reverse proxy.
  TRUST_PROXY_HOP_COUNT: z.coerce.number().int().min(1).default(1),
  ENABLE_ADMIN_PANEL: z.enum(["true", "false"]).default("true"),
  // Token endpoint rate limits. Many services often share one egress IP, and
  // workers often share one client_id, so the defaults are generous but finite
  // (unauthenticated Argon2 hammering from one IP stays bounded).
  RATE_LIMIT_TOKEN_IP_MAX: z.coerce.number().int().positive().default(6000),
  RATE_LIMIT_TOKEN_CLIENT_MAX: z.coerce.number().int().positive().default(600),
  TOKEN_EVENTS_RETENTION_DAYS: z.coerce.number().int().positive().default(30),
});

// Secret values shipped in .env.example and test fixtures. They are public, so
// accepting any of them as a real secret in production is equivalent to having
// no secret at all.
export const KNOWN_PLACEHOLDER_SECRETS = new Set([
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // KEY_ENCRYPTION_SECRET placeholder
]);

/**
 * True when `s` is a short block repeated to fill its length (e.g. the
 * `0123456789abcdef` × 4 example key, or `0000…`). A cryptographically random
 * secret is astronomically unlikely to have this structure.
 */
export function isRepeatedBlock(s: string): boolean {
  for (let blockLen = 1; blockLen <= s.length / 2; blockLen++) {
    if (s.length % blockLen !== 0) continue;
    if (s.slice(0, blockLen).repeat(s.length / blockLen) === s) return true;
  }
  return false;
}

export const productionEnvSchema = envSchema.superRefine((data, ctx) => {
  if (data.NODE_ENV !== "production") return;

  if (!data.PUBLIC_URL.startsWith("https://")) {
    ctx.addIssue({
      code: "custom",
      message: "PUBLIC_URL must use HTTPS in production",
      path: ["PUBLIC_URL"],
    });
  }
  if (KNOWN_PLACEHOLDER_SECRETS.has(data.KEY_ENCRYPTION_SECRET)) {
    ctx.addIssue({
      code: "custom",
      message:
        "KEY_ENCRYPTION_SECRET is the placeholder from .env.example and must be replaced with a freshly generated secret in production (e.g. `openssl rand -hex 32`)",
      path: ["KEY_ENCRYPTION_SECRET"],
    });
  } else if (isRepeatedBlock(data.KEY_ENCRYPTION_SECRET)) {
    ctx.addIssue({
      code: "custom",
      message:
        "KEY_ENCRYPTION_SECRET is a low-entropy repeated pattern; generate a random 32-byte key with `openssl rand -hex 32`",
      path: ["KEY_ENCRYPTION_SECRET"],
    });
  }
  if (data.ADMIN_API_KEY !== undefined && data.ADMIN_API_KEY.length < 48) {
    ctx.addIssue({
      code: "custom",
      message: "ADMIN_API_KEY must be at least 48 characters in production",
      path: ["ADMIN_API_KEY"],
    });
  }
  if (data.CORS_ORIGINS.includes("localhost")) {
    ctx.addIssue({
      code: "custom",
      message: "CORS_ORIGINS must not include localhost in production",
      path: ["CORS_ORIGINS"],
    });
  }
});

export type Env = z.infer<typeof envSchema>;

/** Parse and validate `source`; exits the process on invalid configuration. */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = productionEnvSchema.safeParse(source);
  if (!parsed.success) {
    console.error("Invalid environment variables:");
    console.error(z.flattenError(parsed.error).fieldErrors);
    process.exit(1);
  }

  // Advisory (not fatal): a proxied production deployment with TRUST_PROXY unset
  // collapses per-IP rate limiting and security-log source IPs to one bucket.
  if (parsed.data.NODE_ENV === "production" && parsed.data.TRUST_PROXY !== "true") {
    console.warn(
      "[env] WARNING: NODE_ENV is production but TRUST_PROXY is not 'true'. " +
        "Behind a reverse proxy this collapses per-IP rate limiting and security-log " +
        "source IPs into a single bucket. Set TRUST_PROXY=true (and TRUST_PROXY_HOP_COUNT " +
        "to the number of proxy hops) so client IPs are attributed correctly.",
    );
  }
  return parsed.data;
}

export const env = loadEnv();
