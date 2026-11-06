/**
 * Abstract key-value store for session and rate-limit data.
 * Uses in-memory Map by default; switch to Redis for multi-instance deployments.
 */
export interface KVStore<T> {
  get(key: string): Promise<T | undefined>;
  set(key: string, value: T, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<void>;
  has(key: string): Promise<boolean>;
  clear(): Promise<void>;
  size(): Promise<number>;
}

/**
 * In-memory store implementation suitable for single-instance deployments.
 * Entries with TTL are automatically cleaned up.
 */
export class MemoryStore<T> implements KVStore<T> {
  private store = new Map<string, { value: T; expiresAt?: number }>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  /** `maxKeys` bounds memory: setting a new key at the cap evicts the oldest-inserted one. */
  constructor(
    cleanupIntervalMs = 60_000,
    private readonly maxKeys = Number.POSITIVE_INFINITY,
  ) {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store) {
        if (entry.expiresAt && now > entry.expiresAt) {
          this.store.delete(key);
        }
      }
    }, cleanupIntervalMs);
    this.cleanupInterval.unref();
  }

  async get(key: string): Promise<T | undefined> {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  async set(key: string, value: T, ttlMs?: number): Promise<void> {
    if (!this.store.has(key) && this.store.size >= this.maxKeys) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }
    this.store.set(key, {
      value,
      expiresAt: ttlMs ? Date.now() + ttlMs : undefined,
    });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async has(key: string): Promise<boolean> {
    const val = await this.get(key);
    return val !== undefined;
  }

  async clear(): Promise<void> {
    this.store.clear();
  }

  async size(): Promise<number> {
    return this.store.size;
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }
}
