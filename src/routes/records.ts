import { Router } from 'express';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { createVerifyApiKey, AuthenticatedRequest } from '../middleware/auth';
import { createCommunityAgent } from '../services/atproto';
import { isAdminInList } from '../lib/adminUtils';

/**
 * Collections that only admins can write to.
 * All other community.opensocial.* collections are writable by any member.
 */
const ADMIN_ONLY_COLLECTIONS = new Set([
  'community.opensocial.listitem.status',
  'app.collectivesocial.group.listitem.status',
  'community.opensocial.profile',
  'community.opensocial.admins',
]);

/**
 * Collections that only admins can update (PUT).
 * Lists can be created by anyone but only updated by admins.
 */
const ADMIN_UPDATE_COLLECTIONS = new Set([
  'community.opensocial.list',
  'app.collectivesocial.group.list',
  'community.opensocial.listitem.status',
  'app.collectivesocial.group.listitem.status',
  'community.opensocial.profile',
  'community.opensocial.admins',
]);

/**
 * Check if a user DID is a member of a community by scanning membershipProof records.
 */
async function isMember(communityAgent: any, communityDid: string, userDid: string): Promise<boolean> {
  let cursor: string | undefined;
  do {
    const response = await communityAgent.api.com.atproto.repo.listRecords({
      repo: communityDid,
      collection: 'community.opensocial.membershipProof',
      limit: 100,
      cursor,
    });
    const found = response.data.records.some(
      (r: any) => r.value.memberDid === userDid
    );
    if (found) return true;
    cursor = response.data.cursor;
  } while (cursor);
  return false;
}

/**
 * Check if a user DID is an admin of a community.
 */
async function isAdmin(communityAgent: any, communityDid: string, userDid: string): Promise<boolean> {
  try {
    const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
      repo: communityDid,
      collection: 'community.opensocial.admins',
      rkey: 'self',
    });
    const admins = (adminsResponse.data.value as any).admins || [];
    return isAdminInList(userDid, admins);
  } catch {
    return false;
  }
}

export function createRecordsRouter(db: Kysely<Database>) {
  const router = Router();
  const verifyApiKey = createVerifyApiKey(db);

  /**
   * POST /communities/:did/records
   * Create a record in the community's PDS repo on behalf of a member.
   *
   * Body: { user_did, collection, record, rkey? }
   *
   * Auth: API key + user must be a member. Admin-only collections require admin status.
   */
  router.post('/:did/records', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;
    const { user_did, collection, record, rkey } = req.body;

    if (!user_did || !collection || !record) {
      return res.status(400).json({ error: 'user_did, collection, and record are required' });
    }

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, did);

      // Verify membership (admins are implicitly members)
      const memberCheck = await isMember(communityAgent, did, user_did);
      const adminCheck = await isAdmin(communityAgent, did, user_did);
      if (!memberCheck && !adminCheck) {
        return res.status(403).json({ error: 'User is not a member of this community' });
      }

      // Check admin-only collections
      if (ADMIN_ONLY_COLLECTIONS.has(collection) && !adminCheck) {
        return res.status(403).json({ error: 'Only admins can write to this collection' });
      }

      // Create the record in the community's repo
      const response = await communityAgent.api.com.atproto.repo.createRecord({
        repo: did,
        collection,
        rkey,
        record: {
          $type: collection,
          ...record,
        },
      });

      res.json({
        uri: response.data.uri,
        cid: response.data.cid,
      });
    } catch (error: any) {
      console.error('Error creating community record:', error);
      res.status(500).json({ error: error.message || 'Failed to create record' });
    }
  });

  /**
   * PUT /communities/:did/records
   * Update a record in the community's PDS repo.
   *
   * Body: { user_did, collection, rkey, record }
   *
   * Auth: API key + user must be a member. Admin-update collections require admin status.
   */
  router.put('/:did/records', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;
    const { user_did, collection, rkey, record } = req.body;

    if (!user_did || !collection || !rkey || !record) {
      return res.status(400).json({ error: 'user_did, collection, rkey, and record are required' });
    }

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, did);

      // Verify membership (admins are implicitly members)
      const memberCheck = await isMember(communityAgent, did, user_did);
      const adminCheck = await isAdmin(communityAgent, did, user_did);
      if (!memberCheck && !adminCheck) {
        return res.status(403).json({ error: 'User is not a member of this community' });
      }

      // Check admin-update collections
      if (ADMIN_UPDATE_COLLECTIONS.has(collection) && !adminCheck) {
        return res.status(403).json({ error: 'Only admins can update records in this collection' });
      }

      const response = await communityAgent.api.com.atproto.repo.putRecord({
        repo: did,
        collection,
        rkey,
        record: {
          $type: collection,
          ...record,
        },
      });

      res.json({
        uri: response.data.uri,
        cid: response.data.cid,
      });
    } catch (error: any) {
      console.error('Error updating community record:', error);
      res.status(500).json({ error: error.message || 'Failed to update record' });
    }
  });

  /**
   * DELETE /communities/:did/records/:collection/:rkey
   * Delete a record from the community's PDS repo.
   *
   * Query: ?user_did=…
   *
   * Auth: API key + user must be a member. Admin-only/admin-update collections require admin status.
   */
  router.delete('/:did/records/:collection/:rkey', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did, collection, rkey } = req.params;
    const user_did = req.query.user_did as string;

    if (!user_did) {
      return res.status(400).json({ error: 'user_did query parameter is required' });
    }

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, did);

      // Verify membership (admins are implicitly members)
      const memberCheck = await isMember(communityAgent, did, user_did);
      const adminCheck = await isAdmin(communityAgent, did, user_did);
      if (!memberCheck && !adminCheck) {
        return res.status(403).json({ error: 'User is not a member of this community' });
      }

      // Admin-only or admin-update collections need admin check for deletion
      if ((ADMIN_ONLY_COLLECTIONS.has(collection) || ADMIN_UPDATE_COLLECTIONS.has(collection)) && !adminCheck) {
        return res.status(403).json({ error: 'Only admins can delete records in this collection' });
      }

      await communityAgent.api.com.atproto.repo.deleteRecord({
        repo: did,
        collection,
        rkey,
      });

      res.json({ success: true });
    } catch (error: any) {
      console.error('Error deleting community record:', error);
      res.status(500).json({ error: error.message || 'Failed to delete record' });
    }
  });

  /**
   * GET /communities/:did/records/:collection
   * List records in a specific collection from the community's PDS repo.
   *
   * Query: ?limit=&cursor=
   */
  router.get('/:did/records/:collection', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did, collection } = req.params;
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const cursor = req.query.cursor as string | undefined;

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, did);

      const response = await communityAgent.api.com.atproto.repo.listRecords({
        repo: did,
        collection,
        limit,
        cursor,
      });

      res.json({
        records: response.data.records,
        cursor: response.data.cursor,
      });
    } catch (error: any) {
      console.error('Error listing community records:', error);
      res.status(500).json({ error: error.message || 'Failed to list records' });
    }
  });

  /**
   * GET /communities/:did/records/:collection/:rkey
   * Get a specific record from the community's PDS repo.
   */
  router.get('/:did/records/:collection/:rkey', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did, collection, rkey } = req.params;

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, did);

      const response = await communityAgent.api.com.atproto.repo.getRecord({
        repo: did,
        collection,
        rkey,
      });

      res.json({
        uri: response.data.uri,
        cid: response.data.cid,
        value: response.data.value,
      });
    } catch (error: any) {
      console.error('Error getting community record:', error);
      res.status(500).json({ error: error.message || 'Failed to get record' });
    }
  });

  /**
   * POST /communities/:did/membership/check
   * Check if a user is a member (and/or admin) of a community.
   *
   * Body: { user_did }
   * Returns: { is_member, is_admin }
   */
  router.post('/:did/membership/check', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;
    const { user_did } = req.body;

    if (!user_did) {
      return res.status(400).json({ error: 'user_did is required' });
    }

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, did);

      // Check member and admin status independently.
      // Admins are always considered members even if they lack a membershipProof
      // (e.g. community created before proof records were introduced).
      const memberCheck = await isMember(communityAgent, did, user_did);
      const adminCheck = await isAdmin(communityAgent, did, user_did);

      res.json({
        is_member: memberCheck || adminCheck,
        is_admin: adminCheck,
      });
    } catch (error: any) {
      console.error('Error checking membership:', error);
      res.status(500).json({ error: error.message || 'Failed to check membership' });
    }
  });

  return router;
}
