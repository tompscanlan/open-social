/**
 * Shared utilities for admin list operations.
 *
 * The admins record (community.opensocial.admins) historically has two formats:
 *   - Legacy: string[]  (just DIDs)
 *   - Canonical: Array<{ did: string; addedAt?: string }>  (matches lexicon)
 *
 * These helpers handle both transparently.
 */

export interface AdminEntry {
  did: string;
  addedAt: string;
}

/**
 * Check whether a DID appears in an admin list, regardless of format.
 */
export function isAdminInList(did: string, admins: any[]): boolean {
  return admins.some((admin: any) => {
    if (typeof admin === 'string') return admin === did;
    return admin.did === did;
  });
}

/**
 * Return the DID of the original/first admin (the group creator).
 * This admin can never be demoted.
 */
export function getOriginalAdminDid(admins: any[]): string | null {
  if (!admins || admins.length === 0) return null;
  const first = admins[0];
  return typeof first === 'string' ? first : first.did;
}

/**
 * Convert an admin list from any supported format into the canonical
 * object format that matches the community.opensocial.admins lexicon.
 */
export function normalizeAdmins(admins: any[]): AdminEntry[] {
  return admins.map((admin: any) => {
    if (typeof admin === 'string') {
      return { did: admin, addedAt: new Date().toISOString() };
    }
    return {
      did: admin.did,
      addedAt: admin.addedAt || new Date().toISOString(),
    };
  });
}
