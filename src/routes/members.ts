import { Router } from 'express';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { createVerifyApiKey, AuthenticatedRequest } from '../middleware/auth';

export function createMemberRouter(db: Kysely<Database>) {
  const router = Router();
  const verifyApiKey = createVerifyApiKey(db);

  // Get join information (client creates record in user's repo)
  router.post('/:did/members', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;
    const { user_did, user_pds_host } = req.body;

    if (!user_did || !user_pds_host) {
      return res.status(400).json({
        error: 'user_did and user_pds_host required',
      });
    }

    try {
      const community = await db
        .selectFrom('communities')
        .select(['did', 'handle', 'pds_host'])
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      res.json({
        action: 'create_membership_record',
        instructions: "Use the user's authenticated agent to create this record in their repo",
        record: {
          $type: 'community.opensocial.membership',
          community: community.did,
          joinedAt: new Date().toISOString(),
        },
        collection: 'community.opensocial.membership',
        community: {
          handle: community.handle,
          did: community.did,
        },
      });
    } catch (error) {
      console.error('Error processing join request:', error);
      res.status(500).json({ error: 'Failed to process join request' });
    }
  });

  // List members (placeholder - requires firehose subscription)
  router.get('/:did/members', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      res.json({
        members: [],
        note: 'Member discovery requires firehose subscription or manual tracking',
      });
    } catch (error) {
      console.error('Error fetching members:', error);
      res.status(500).json({ error: 'Failed to fetch members' });
    }
  });

  return router;
}
