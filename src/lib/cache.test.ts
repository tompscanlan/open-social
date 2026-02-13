/**
 * Integration tests for cache.ts
 * Tests the TTL cache functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TtlCache } from '../lib/cache';

describe('cache.ts - TtlCache', () => {
  let cache: TtlCache<string>;

  beforeEach(() => {
    cache = new TtlCache<string>(1000); // 1 second TTL for tests
  });

  describe('set and get', () => {
    it('should store and retrieve values', () => {
      cache.set('key1', 'value1');
      expect(cache.get('key1')).toBe('value1');
    });

    it('should return undefined for non-existent keys', () => {
      expect(cache.get('non-existent')).toBeUndefined();
    });

    it('should overwrite existing values', () => {
      cache.set('key1', 'value1');
      cache.set('key1', 'value2');
      expect(cache.get('key1')).toBe('value2');
    });

    it('should handle multiple keys', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');

      expect(cache.get('key1')).toBe('value1');
      expect(cache.get('key2')).toBe('value2');
      expect(cache.get('key3')).toBe('value3');
    });
  });

  describe('TTL expiration', () => {
    it('should expire values after TTL', async () => {
      const shortCache = new TtlCache<string>(50); // 50ms TTL
      shortCache.set('key1', 'value1');

      expect(shortCache.get('key1')).toBe('value1');

      // Wait for TTL to expire
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(shortCache.get('key1')).toBeUndefined();
    });

    it('should not expire values before TTL', async () => {
      const longCache = new TtlCache<string>(500); // 500ms TTL
      longCache.set('key1', 'value1');

      // Wait less than TTL
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(longCache.get('key1')).toBe('value1');
    });
  });

  describe('invalidate', () => {
    it('should remove a specific key', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');

      cache.invalidate('key1');

      expect(cache.get('key1')).toBeUndefined();
      expect(cache.get('key2')).toBe('value2');
    });

    it('should handle invalidating non-existent keys', () => {
      expect(() => cache.invalidate('non-existent')).not.toThrow();
    });
  });

  describe('invalidatePrefix', () => {
    it('should remove all keys with matching prefix', () => {
      cache.set('user:123:profile', 'profile1');
      cache.set('user:123:settings', 'settings1');
      cache.set('user:456:profile', 'profile2');
      cache.set('other:key', 'value');

      cache.invalidatePrefix('user:123');

      expect(cache.get('user:123:profile')).toBeUndefined();
      expect(cache.get('user:123:settings')).toBeUndefined();
      expect(cache.get('user:456:profile')).toBe('profile2');
      expect(cache.get('other:key')).toBe('value');
    });

    it('should handle empty prefixes', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');

      cache.invalidatePrefix('');

      // Empty prefix should clear all
      expect(cache.get('key1')).toBeUndefined();
      expect(cache.get('key2')).toBeUndefined();
    });

    it('should handle prefix with no matches', () => {
      cache.set('key1', 'value1');

      expect(() => cache.invalidatePrefix('no-match')).not.toThrow();
      expect(cache.get('key1')).toBe('value1');
    });
  });

  describe('clear', () => {
    it('should remove all entries', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');

      cache.clear();

      expect(cache.get('key1')).toBeUndefined();
      expect(cache.get('key2')).toBeUndefined();
      expect(cache.get('key3')).toBeUndefined();
    });

    it('should allow adding entries after clear', () => {
      cache.set('key1', 'value1');
      cache.clear();

      cache.set('key2', 'value2');
      expect(cache.get('key2')).toBe('value2');
    });
  });

  describe('complex objects', () => {
    it('should handle object values', () => {
      const obj = { name: 'John', age: 30 };
      cache.set('user', obj as any);

      expect(cache.get('user')).toEqual(obj);
    });

    it('should handle array values', () => {
      const arr = ['item1', 'item2', 'item3'];
      cache.set('list', arr as any);

      expect(cache.get('list')).toEqual(arr);
    });
  });

  describe('cache key patterns', () => {
    it('should handle colon-separated keys', () => {
      cache.set('did:plc:123:member', 'value1');
      cache.set('did:plc:456:member', 'value2');

      expect(cache.get('did:plc:123:member')).toBe('value1');
      expect(cache.get('did:plc:456:member')).toBe('value2');
    });

    it('should handle URL-like keys', () => {
      cache.set('https://example.com/resource', 'value');
      expect(cache.get('https://example.com/resource')).toBe('value');
    });
  });
});
