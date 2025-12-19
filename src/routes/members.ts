import { Router } from 'express';
import pool from '../services/database';
import { verifyApiKey, AuthenticatedRequest } from '../middleware/auth';

const router = Router();

// Get join information (client creates record in user's repo)
router.post('/:communityId/members', verifyApiKey, async (req: AuthenticatedRequest, res) => {
  const { communityId } = req.params;
  const { user_did, user_pds_host } = req.body;

  if (!user_did || !user_pds_host) {
    return res.status(400).json({
      error: 'user_did and user_pds_host required',
    });
  }

  try {
    const communityResult = await pool.query(
      'SELECT * FROM communities WHERE community_id = $1 AND app_id = $2',
      [communityId, req.app_data!.app_id]
    );

    if (communityResult.rows.length === 0) {
      return res.status(404).json({ error: 'Community not found' });
    }

    const community = communityResult.rows[0];

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
        community_id: community.community_id,
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
router.get('/:communityId/members', verifyApiKey, async (req: AuthenticatedRequest, res) => {
  const { communityId } = req.params;

  try {
    const communityResult = await pool.query(
      'SELECT * FROM communities WHERE community_id = $1',
      [communityId]
    );

    if (communityResult.rows.length === 0) {
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

export default router;
