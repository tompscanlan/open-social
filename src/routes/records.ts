import { Router } from 'express';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { createVerifyApiKey, type AuthenticatedRequest } from '../middleware/auth';
import {
  createRecordSchema,
  updateRecordSchema,
  deleteRecordSchema,
  listRecordsSchema,
  membershipCheckSchema,
} from '../validation/schemas';
import { isAdminInList } from '../lib/adminUtils';
import { createCommunityAgent } from '../services/atproto';
import { createWebhookService } from '../services/webhook';

/**
 * Collections that only admins can write to.
 */
const ADMIN_ONLY_COLLECTIONS = new Set([
  'community.opensocial.listitem.status',
  'community.opensocial.profile',
  'community.opensocial.admins',
]);

/**
 * Collections that only admins can update (PUT).
 */
const ADMIN_UPDATE_COLLECTIONS = new Set([
  'community.opensocial.list',
  'community.opensocial.listitem.status',
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

export function createRecordsRouter(db: Kysely<Database>): Router {
  const router = Router();
  const verifyApiKey = createVerifyApiKey(db);
  const webhooks = createWebhookService(db);

  /**
   * POST /communities/:did/records
   * Create a record in the community's PDS repo on behalf of a member.
   *
   * Body: { userDid, collection, record, rkey? }
   */
  router.post('/:did/records', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const communityDid = decodeURIComponent(req.params.did);
      const parsed = createRecordSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { userDid, collection, record, rkey } = parsed.data;

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      // Verify membership (admins are implicitly members)
      const memberCheck = await isMember(communityAgent, communityDid, userDid);
      const adminCheck = await isAdmin(communityAgent, communityDid, userDid);
      if (!memberCheck && !adminCheck) {
        return res.status(403).json({ error: 'User is not a member of this community' });
      }

      // Check admin-only collections
      if (ADMIN_ONLY_COLLECTIONS.has(collection) && !adminCheck) {
        return res.status(403).json({ error: 'Only admins can write to this collection' });
      }

      const response = await communityAgent.api.com.atproto.repo.createRecord({
        repo: communityDid,
        collection,
        rkey,
        record: {
          $type: collection,
          ...record,
        },
      });

      await webhooks.dispatch('record.created', communityDid, {
        communityDid,
        collection,
        uri: response.data.uri,
        userDid,
      });

      res.status(201).json({
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
   * Body: { userDid, collection, rkey, record }
   */
  router.put('/:did/records', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const communityDid = decodeURIComponent(req.params.did);
      const parsed = updateRecordSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { userDid, collection, rkey, record } = parsed.data;

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      // Verify membership
      const memberCheck = await isMember(communityAgent, communityDid, userDid);
      const adminCheck = await isAdmin(communityAgent, communityDid, userDid);
      if (!memberCheck && !adminCheck) {
        return res.status(403).json({ error: 'User is not a member of this community' });
      }

      // Check admin-update collections
      if (ADMIN_UPDATE_COLLECTIONS.has(collection) && !adminCheck) {
        return res.status(403).json({ error: 'Only admins can update records in this collection' });
      }

      const response = await communityAgent.api.com.atproto.repo.putRecord({
        repo: communityDid,
        collection,
        rkey,
        record: {
          $type: collection,
          ...record,
        },
      });

      await webhooks.dispatch('record.updated', communityDid, {
        communityDid,
        collection,
        rkey,
        uri: response.data.uri,
        userDid,
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
   * Query: ?userDid=...
   */
  router.delete('/:did/records/:collection/:rkey', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const communityDid = decodeURIComponent(req.params.did);
      const { collection, rkey } = req.params;
      const parsed = deleteRecordSchema.safeParse(req.query);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid query', details: parsed.error.flatten() });
      }

      const { userDid } = parsed.data;

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      // Verify membership
      const memberCheck = await isMember(communityAgent, communityDid, userDid);
      const adminCheck = await isAdmin(communityAgent, communityDid, userDid);
      if (!memberCheck && !adminCheck) {
        return res.status(403).json({ error: 'User is not a member of this community' });
      }

      // Admin-only or admin-update collections need admin check for deletion
      if ((ADMIN_ONLY_COLLECTIONS.has(collection) || ADMIN_UPDATE_COLLECTIONS.has(collection)) && !adminCheck) {
        return res.status(403).json({ error: 'Only admins can delete records in this collection' });
      }

      await communityAgent.api.com.atproto.repo.deleteRecord({
        repo: communityDid,
        collection,
        rkey,
      });

      await webhooks.dispatch('record.deleted', communityDid, {
        communityDid,
        collection,
        rkey,
        userDid,
      });

      res.json({ success: true });
    } catch (error: any) {
      console.error('Error deleting community record:', error);
      res.status(500).json({ error: error.message || 'Failed to delete record' });
    }
  });

  /**
   * GET /communities/:did/records/:collection
   * List records in a specific collection.
   */
  router.get('/:did/records/:collection', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const communityDid = decodeURIComponent(req.params.did);
      const { collection } = req.params;
      const parsed = listRecordsSchema.safeParse(req.query);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid query', details: parsed.error.flatten() });
      }

      const { limit, cursor } = parsed.data;

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      const response = await communityAgent.api.com.atproto.repo.listRecords({
        repo: communityDid,
        collection,
        limit,
        cursor,
      });

      res.json({
        records: response.data.records,
        cursor: response.data.cursor || undefined,
      });
    } catch (error: any) {
      console.error('Error listing community records:', error);
      res.status(500).json({ error: error.message || 'Failed to list records' });
    }
  });

  /**
   * GET /communities/:did/records/:collection/:rkey
   * Get a specific record.
   */
  router.get('/:did/records/:collection/:rkey', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const communityDid = decodeURIComponent(req.params.did);
      const { collection, rkey } = req.params;

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      const response = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
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

  return router;
}
