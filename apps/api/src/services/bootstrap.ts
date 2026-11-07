import { adminUsers, db } from "@handsal/db";
import { env } from "../env.js";
import { ApiError } from "../middleware/error-handler.js";
import { createLogger } from "../utils/logger.js";
import { createAdminUser } from "./admin-user.service.js";

const logger = createLogger("bootstrap");

interface BootstrapConfig {
  email?: string;
  password?: string;
}

/**
 * Creates the first super-admin from BOOTSTRAP_ADMIN_* when admin_users is empty.
 * `config` is injectable for tests (env is read once at import). Never logs the password.
 * When BOOTSTRAP_ADMIN_PASSWORD was in the environment at entry, it is removed from
 * process.env before return so the secret does not linger after startup.
 */
export async function bootstrapAdmin({
  email = env.BOOTSTRAP_ADMIN_EMAIL,
  password = env.BOOTSTRAP_ADMIN_PASSWORD,
}: BootstrapConfig = {}): Promise<void> {
  const hadBootstrapPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD !== undefined;
  try {
    if (!email || !password) {
      logger.debug("Skipping admin bootstrap: BOOTSTRAP_ADMIN_EMAIL/PASSWORD not set");
      return;
    }
    const [existing] = await db.select({ id: adminUsers.id }).from(adminUsers).limit(1);
    if (existing) {
      logger.debug("Skipping admin bootstrap: admin users already exist");
      return;
    }
    try {
      await createAdminUser({ email, password, name: "Administrator", isSuperAdmin: true });
    } catch (err) {
      // Another instance bootstrapped concurrently.
      if (err instanceof ApiError && err.errorCode === "email_exists") return;
      throw err;
    }
    logger.info({ email }, "Bootstrapped super-admin");
  } finally {
    if (hadBootstrapPassword) {
      delete process.env.BOOTSTRAP_ADMIN_PASSWORD;
      logger.info(
        "Remove BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD from the deployment environment now that an admin exists",
      );
    }
  }
}
