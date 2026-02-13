/**
 * Unit tests for adminUtils.ts
 * Tests admin list manipulation and format handling
 */

import { describe, it, expect } from 'vitest';
import { isAdminInList, getOriginalAdminDid, normalizeAdmins, type AdminEntry } from '../lib/adminUtils';
import { createFakeDid } from '../test/helpers';

describe('adminUtils.ts', () => {
  const did1 = createFakeDid();
  const did2 = createFakeDid();
  const did3 = createFakeDid();

  describe('isAdminInList', () => {
    it('should find DID in legacy string array format', () => {
      const admins = [did1, did2, did3];

      expect(isAdminInList(did1, admins)).toBe(true);
      expect(isAdminInList(did2, admins)).toBe(true);
      expect(isAdminInList(did3, admins)).toBe(true);
    });

    it('should find DID in canonical object format', () => {
      const admins = [
        { did: did1, addedAt: '2024-01-01T00:00:00Z' },
        { did: did2, addedAt: '2024-01-02T00:00:00Z' },
        { did: did3, addedAt: '2024-01-03T00:00:00Z' },
      ];

      expect(isAdminInList(did1, admins)).toBe(true);
      expect(isAdminInList(did2, admins)).toBe(true);
      expect(isAdminInList(did3, admins)).toBe(true);
    });

    it('should find DID in mixed format array', () => {
      const admins = [
        did1,
        { did: did2, addedAt: '2024-01-02T00:00:00Z' },
        did3,
      ];

      expect(isAdminInList(did1, admins)).toBe(true);
      expect(isAdminInList(did2, admins)).toBe(true);
      expect(isAdminInList(did3, admins)).toBe(true);
    });

    it('should return false for DID not in list', () => {
      const admins = [did1, did2];
      const otherDid = createFakeDid();

      expect(isAdminInList(otherDid, admins)).toBe(false);
    });

    it('should handle empty admin list', () => {
      expect(isAdminInList(did1, [])).toBe(false);
    });

    it('should handle case-sensitive comparison', () => {
      const admins = [did1.toLowerCase()];

      expect(isAdminInList(did1.toUpperCase(), admins)).toBe(false);
    });
  });

  describe('getOriginalAdminDid', () => {
    it('should return first DID from legacy string array', () => {
      const admins = [did1, did2, did3];

      expect(getOriginalAdminDid(admins)).toBe(did1);
    });

    it('should return first DID from canonical object format', () => {
      const admins = [
        { did: did1, addedAt: '2024-01-01T00:00:00Z' },
        { did: did2, addedAt: '2024-01-02T00:00:00Z' },
      ];

      expect(getOriginalAdminDid(admins)).toBe(did1);
    });

    it('should return first DID from mixed format', () => {
      const admins = [
        did1,
        { did: did2, addedAt: '2024-01-02T00:00:00Z' },
      ];

      expect(getOriginalAdminDid(admins)).toBe(did1);
    });

    it('should return null for empty list', () => {
      expect(getOriginalAdminDid([])).toBeNull();
    });

    it('should return null for null/undefined input', () => {
      expect(getOriginalAdminDid(null as any)).toBeNull();
      expect(getOriginalAdminDid(undefined as any)).toBeNull();
    });

    it('should handle single admin', () => {
      expect(getOriginalAdminDid([did1])).toBe(did1);
      expect(getOriginalAdminDid([{ did: did1, addedAt: '2024-01-01T00:00:00Z' }])).toBe(did1);
    });
  });

  describe('normalizeAdmins', () => {
    it('should convert legacy string array to canonical format', () => {
      const admins = [did1, did2, did3];
      const normalized = normalizeAdmins(admins);

      expect(normalized).toHaveLength(3);
      expect(normalized[0].did).toBe(did1);
      expect(normalized[0].addedAt).toBeDefined();
      expect(normalized[1].did).toBe(did2);
      expect(normalized[1].addedAt).toBeDefined();
      expect(normalized[2].did).toBe(did3);
      expect(normalized[2].addedAt).toBeDefined();
    });

    it('should preserve canonical format', () => {
      const timestamp1 = '2024-01-01T00:00:00Z';
      const timestamp2 = '2024-01-02T00:00:00Z';
      const admins = [
        { did: did1, addedAt: timestamp1 },
        { did: did2, addedAt: timestamp2 },
      ];
      const normalized = normalizeAdmins(admins);

      expect(normalized).toHaveLength(2);
      expect(normalized[0]).toEqual({ did: did1, addedAt: timestamp1 });
      expect(normalized[1]).toEqual({ did: did2, addedAt: timestamp2 });
    });

    it('should add addedAt timestamp to objects missing it', () => {
      const admins = [
        { did: did1 },
        { did: did2, addedAt: '2024-01-02T00:00:00Z' },
      ];
      const normalized = normalizeAdmins(admins);

      expect(normalized[0].did).toBe(did1);
      expect(normalized[0].addedAt).toBeDefined();
      expect(new Date(normalized[0].addedAt)).toBeInstanceOf(Date);
      expect(normalized[1].addedAt).toBe('2024-01-02T00:00:00Z');
    });

    it('should handle mixed format array', () => {
      const timestamp = '2024-01-02T00:00:00Z';
      const admins = [
        did1,
        { did: did2, addedAt: timestamp },
        did3,
      ];
      const normalized = normalizeAdmins(admins);

      expect(normalized).toHaveLength(3);
      expect(normalized[0].did).toBe(did1);
      expect(normalized[0].addedAt).toBeDefined();
      expect(normalized[1]).toEqual({ did: did2, addedAt: timestamp });
      expect(normalized[2].did).toBe(did3);
      expect(normalized[2].addedAt).toBeDefined();
    });

    it('should handle empty array', () => {
      const normalized = normalizeAdmins([]);

      expect(normalized).toEqual([]);
    });

    it('should generate ISO timestamp for new entries', () => {
      const admins = [did1];
      const normalized = normalizeAdmins(admins);

      const timestamp = normalized[0].addedAt;
      expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);

      // Verify it's a recent timestamp (within last minute)
      const date = new Date(timestamp);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      expect(diffMs).toBeLessThan(60000); // Less than 1 minute
    });

    it('should preserve order of admins', () => {
      const admins = [did3, did1, did2];
      const normalized = normalizeAdmins(admins);

      expect(normalized[0].did).toBe(did3);
      expect(normalized[1].did).toBe(did1);
      expect(normalized[2].did).toBe(did2);
    });
  });

  describe('integration scenarios', () => {
    it('should support round-trip conversion', () => {
      // Legacy -> Canonical -> Check membership
      const legacyAdmins = [did1, did2, did3];
      const normalized = normalizeAdmins(legacyAdmins);

      expect(isAdminInList(did1, normalized)).toBe(true);
      expect(isAdminInList(did2, normalized)).toBe(true);
      expect(isAdminInList(did3, normalized)).toBe(true);
      expect(getOriginalAdminDid(normalized)).toBe(did1);
    });

    it('should handle admin promotion workflow', () => {
      // Start with one admin (creator)
      let admins: any[] = [did1];
      expect(getOriginalAdminDid(admins)).toBe(did1);

      // Promote a new admin
      admins.push({ did: did2, addedAt: new Date().toISOString() });
      expect(isAdminInList(did2, admins)).toBe(true);

      // Original admin should still be first
      expect(getOriginalAdminDid(admins)).toBe(did1);

      // Normalize the list
      const normalized = normalizeAdmins(admins);
      expect(normalized).toHaveLength(2);
      expect(getOriginalAdminDid(normalized)).toBe(did1);
    });

    it('should support migration from legacy to canonical format', () => {
      // Legacy format from database
      const legacyAdmins = [did1, did2, did3];

      // Migrate to canonical
      const canonical = normalizeAdmins(legacyAdmins);

      // Verify all DIDs preserved
      expect(canonical.map(a => a.did)).toEqual([did1, did2, did3]);

      // Verify all have timestamps
      canonical.forEach(admin => {
        expect(admin.addedAt).toBeDefined();
        expect(new Date(admin.addedAt)).toBeInstanceOf(Date);
      });
    });
  });
});
