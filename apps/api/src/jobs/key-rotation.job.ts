import { autoRotateDueKeys, retireExpiredKeys } from "../services/signing-key.service.js";
import type { Job } from "./index.js";

/** Hourly: drop expired retiring keys from JWKS, then rotate tenants due for auto-rotation. */
export const keyRotationJob: Job = {
  name: "key-rotation",
  intervalMs: 60 * 60 * 1000,
  run: async () => {
    await retireExpiredKeys();
    await autoRotateDueKeys();
  },
};
