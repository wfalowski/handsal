import pino from "pino";
import { env } from "../env.js";

/**
 * pino's default error serializer copies ALL enumerable error properties
 * (nested cause chains, driver internals, ...) into the log event. Keep the
 * shape to a fixed key set.
 */
function serializeError(err: unknown): Record<string, unknown> {
  if (!(err instanceof Error)) {
    return { message: String(err) };
  }

  const result: Record<string, unknown> = {
    type: err.name,
    message: appendCauseMessages(err),
    stack: err.stack,
  };

  const code = (err as { code?: unknown }).code;
  if (typeof code === "string" || typeof code === "number") {
    result.code = code;
  }

  return result;
}

/** Fold a `cause` chain into the message string instead of nesting objects. */
function appendCauseMessages(err: Error, maxDepth = 3): string {
  let message = err.message;
  let cause: unknown = err.cause;

  for (let depth = 0; depth < maxDepth && cause instanceof Error; depth += 1) {
    message += ` [cause: ${cause.message}]`;
    cause = cause.cause;
  }

  return message;
}

// JSON to stdout; shipping logs elsewhere is the platform's job.
export const rootLogger = pino({
  level: env.LOG_LEVEL,
  base: { service: "handsal", env: env.NODE_ENV },
  serializers: { err: serializeError },
  // Paths that must never appear in logs
  redact: {
    paths: [
      "req.headers.authorization",
      "headers.authorization",
      "authorization",
      "clientSecret",
      "client_secret",
      "password",
      "passwordHash",
      "privateKey",
      "KEY_ENCRYPTION_SECRET",
    ],
    censor: "[Redacted]",
  },
});

/** Create a child logger scoped to a module name. */
export function createLogger(name: string) {
  return rootLogger.child({ module: name });
}
