import { createLogger } from "../utils/logger.js";

const logger = createLogger("bootstrap");

/** Creates the first super-admin from BOOTSTRAP_ADMIN_* when admin_users is empty. */
export async function bootstrapAdmin(): Promise<void> {
  logger.info("bootstrap: not implemented yet (task 3.1)");
}
