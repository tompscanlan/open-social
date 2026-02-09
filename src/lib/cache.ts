/**
 * Simple in-memory TTL cache.
 *
 * Used to avoid repeated PDS round-trips for admin/membership checks
 * that happen on nearly every request.  Entries expire after `ttlMs`
 * milliseconds and are lazily evicted on read.
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class TtlCache<T = unknown> {
  private store = new Map<string, CacheEntry<T>>();
  private readonly ttlMs: number;

  /** @param ttlMs  Time-to-live in milliseconds (default 30 s) */
  constructor(ttlMs = 30_000) {
    this.ttlMs = ttlMs;
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: T): void {
    this.store.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  /** Remove a single key (useful after a mutation that invalidates the cache). */
  invalidate(key: string): void {
    this.store.delete(key);
  }

  /** Remove all keys whose prefix matches (e.g. invalidate all entries for a community). */
  invalidatePrefix(prefix: string): void {
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) {
        this.store.delete(key);
      }
    }
  }

  clear(): void {
    this.store.clear();
  }
}

// ─── Shared singleton caches ──────────────────────────────────────────

/** Cache for "is DID an admin of community?" — key: `${communityDid}:${userDid}` */
export const adminCache = new TtlCache<boolean>(30_000);

/** Cache for "is DID a member of community?" — key: `${communityDid}:${userDid}` */
export const memberCache = new TtlCache<boolean>(30_000);

/** Cache for user roles in a community — key: `${communityDid}:${userDid}`, value: role names */
export const memberRolesCache = new TtlCache<string[]>(30_000);
