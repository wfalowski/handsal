import { existsSync } from "fs";
import { dirname, join, parse } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  findRepoRoot,
  isRepeatedBlock,
  KNOWN_PLACEHOLDER_SECRETS,
  productionEnvSchema,
} from "./env.js";

// A high-entropy 64-hex value that is NOT a repeated block, standing in for a
// real `openssl rand -hex 32` KEY_ENCRYPTION_SECRET.
const REAL_ENC_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90fedcba9876543210abcdef0123456789";
const PLACEHOLDER_ENC_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function prodEnv(overrides: Record<string, string> = {}) {
  return {
    NODE_ENV: "production",
    DATABASE_URL: "postgresql://u:p@db:5432/app",
    PUBLIC_URL: "https://auth.example.com",
    KEY_ENCRYPTION_SECRET: REAL_ENC_SECRET,
    CORS_ORIGINS: "https://admin.example.com",
    ...overrides,
  };
}

function fieldErrors(input: Record<string, string>) {
  const result = productionEnvSchema.safeParse(input);
  return result.success ? {} : z.flattenError(result.error).fieldErrors;
}

describe("findRepoRoot", () => {
  it("walks up to the directory holding pnpm-workspace.yaml", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const root = findRepoRoot(here);
    expect(root).toBeDefined();
    expect(existsSync(join(root as string, "pnpm-workspace.yaml"))).toBe(true);
    expect(findRepoRoot(join(here, "..", "dist"))).toBe(root);
  });

  it("returns undefined when no workspace file exists up to the filesystem root", () => {
    expect(findRepoRoot(parse(process.cwd()).root)).toBeUndefined();
  });
});

describe("isRepeatedBlock", () => {
  it("detects the committed example key and trivial repeats", () => {
    expect(isRepeatedBlock(PLACEHOLDER_ENC_SECRET)).toBe(true);
    expect(isRepeatedBlock("0".repeat(64))).toBe(true);
    expect(isRepeatedBlock("abab")).toBe(true);
  });

  it("does not flag a high-entropy value", () => {
    expect(isRepeatedBlock(REAL_ENC_SECRET)).toBe(false);
  });
});

describe("productionEnvSchema", () => {
  it("accepts a fully-configured production env and applies defaults", () => {
    const result = productionEnvSchema.safeParse(prodEnv());
    expect(result.success).toBe(true);
    expect(result.data).toMatchObject({
      PORT: 3000,
      LOG_LEVEL: "info",
      ENABLE_ADMIN_PANEL: "true",
      RATE_LIMIT_TOKEN_IP_MAX: 6000,
      RATE_LIMIT_TOKEN_CLIENT_MAX: 600,
      TOKEN_EVENTS_RETENTION_DAYS: 30,
    });
  });

  it("rejects the placeholder KEY_ENCRYPTION_SECRET in production", () => {
    expect(KNOWN_PLACEHOLDER_SECRETS.has(PLACEHOLDER_ENC_SECRET)).toBe(true);
    expect(
      fieldErrors(prodEnv({ KEY_ENCRYPTION_SECRET: PLACEHOLDER_ENC_SECRET })).KEY_ENCRYPTION_SECRET,
    ).toBeDefined();
  });

  it("rejects a repeated-block KEY_ENCRYPTION_SECRET that is not a known placeholder", () => {
    expect(
      fieldErrors(prodEnv({ KEY_ENCRYPTION_SECRET: "0".repeat(64) })).KEY_ENCRYPTION_SECRET,
    ).toBeDefined();
  });

  it("rejects an http:// PUBLIC_URL in production", () => {
    expect(
      fieldErrors(prodEnv({ PUBLIC_URL: "http://auth.example.com" })).PUBLIC_URL,
    ).toBeDefined();
  });

  it("rejects a 32-char ADMIN_API_KEY in production but accepts 48", () => {
    expect(fieldErrors(prodEnv({ ADMIN_API_KEY: "k".repeat(32) })).ADMIN_API_KEY).toBeDefined();
    expect(fieldErrors(prodEnv({ ADMIN_API_KEY: "k".repeat(48) })).ADMIN_API_KEY).toBeUndefined();
  });

  it("rejects localhost CORS_ORIGINS in production", () => {
    expect(
      fieldErrors(prodEnv({ CORS_ORIGINS: "http://localhost:5173" })).CORS_ORIGINS,
    ).toBeDefined();
  });

  it("allows dev placeholders outside production", () => {
    const dev = {
      NODE_ENV: "development",
      DATABASE_URL: "postgresql://handsal:handsal_dev@localhost:5434/handsal",
      PUBLIC_URL: "http://localhost:3000",
      KEY_ENCRYPTION_SECRET: PLACEHOLDER_ENC_SECRET,
      ADMIN_API_KEY: "k".repeat(32),
    };
    expect(productionEnvSchema.safeParse(dev).success).toBe(true);
  });

  it("strips trailing slashes from PUBLIC_URL", () => {
    const result = productionEnvSchema.safeParse(
      prodEnv({ PUBLIC_URL: "https://auth.example.com/" }),
    );
    expect(result.data?.PUBLIC_URL).toBe("https://auth.example.com");
  });

  it("requires BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD together", () => {
    const onlyEmail = fieldErrors(
      prodEnv({ NODE_ENV: "development", BOOTSTRAP_ADMIN_EMAIL: "admin@example.com" }),
    );
    expect(onlyEmail.BOOTSTRAP_ADMIN_PASSWORD).toBeDefined();
    expect(onlyEmail.BOOTSTRAP_ADMIN_EMAIL).toBeUndefined();

    const onlyPassword = fieldErrors(prodEnv({ BOOTSTRAP_ADMIN_PASSWORD: "s3cret-passphrase" }));
    expect(onlyPassword.BOOTSTRAP_ADMIN_EMAIL).toBeDefined();
    expect(onlyPassword.BOOTSTRAP_ADMIN_PASSWORD).toBeUndefined();

    const both = prodEnv({
      BOOTSTRAP_ADMIN_EMAIL: "admin@example.com",
      BOOTSTRAP_ADMIN_PASSWORD: "s3cret-passphrase",
    });
    expect(productionEnvSchema.safeParse(both).success).toBe(true);
  });

  it("rejects the .env.example BOOTSTRAP_ADMIN_PASSWORD placeholder in production", () => {
    expect(KNOWN_PLACEHOLDER_SECRETS.has("change-me-before-first-start")).toBe(true);
    // Long enough for min(12), so this fails on the placeholder check alone.
    expect(
      fieldErrors(
        prodEnv({
          BOOTSTRAP_ADMIN_EMAIL: "admin@example.com",
          BOOTSTRAP_ADMIN_PASSWORD: "change-me-before-first-start",
        }),
      ).BOOTSTRAP_ADMIN_PASSWORD,
    ).toEqual([expect.stringContaining("placeholder")]);
  });

  it("rejects a 31-char ADMIN_API_KEY everywhere", () => {
    expect(
      fieldErrors(prodEnv({ NODE_ENV: "development", ADMIN_API_KEY: "k".repeat(31) }))
        .ADMIN_API_KEY,
    ).toBeDefined();
  });
});
