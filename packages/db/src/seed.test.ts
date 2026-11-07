import { afterAll, describe, expect, it } from "vitest";
import { pool } from "./client.js";
import { seedDatabaseHostAllowed } from "./seed.js";

afterAll(async () => {
  await pool.end();
});

describe("seedDatabaseHostAllowed", () => {
  it("allows loopback hosts", () => {
    expect(seedDatabaseHostAllowed("postgresql://handsal:handsal_dev@localhost:5434/handsal")).toBe(
      true,
    );
    expect(seedDatabaseHostAllowed("postgresql://handsal:pw@127.0.0.1:5434/handsal")).toBe(true);
    expect(seedDatabaseHostAllowed("postgresql://handsal:pw@[::1]:5434/handsal")).toBe(true);
    expect(seedDatabaseHostAllowed("postgresql://LOCALHOST:5434/handsal")).toBe(true);
  });

  it("rejects missing, unparseable, and non-loopback hosts", () => {
    expect(seedDatabaseHostAllowed(undefined)).toBe(false);
    expect(seedDatabaseHostAllowed("")).toBe(false);
    expect(seedDatabaseHostAllowed("not a url")).toBe(false);
    expect(seedDatabaseHostAllowed("postgresql://handsal:pw@::1:5434/handsal")).toBe(false);
    expect(seedDatabaseHostAllowed("postgresql://handsal:pw@postgres:5432/handsal")).toBe(false);
    expect(seedDatabaseHostAllowed("postgresql://handsal:pw@10.1.2.3:5432/handsal")).toBe(false);
    expect(seedDatabaseHostAllowed("postgresql://handsal:pw@db.example.com/handsal")).toBe(false);
  });
});
