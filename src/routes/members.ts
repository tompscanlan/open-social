import { Router } from 'express';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { createVerifyApiKey, AuthenticatedRequest } from '../middleware/auth';
import { createCommunityAgent } from '../services/atproto';
import { isAdminInList, getOriginalAdminDid, normalizeAdmins } from '../lib/adminUtils';

export function createMemberRouter(db: Kysely<Database>) {
  const router = Router();
  const verifyApiKey = createVerifyApiKey(db);

  // Get join information (client creates record in user's repo)
  // For open communities, also creates membershipProof in the community's repo.
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

      // For open communities, immediately create membershipProof in community's repo
      // so the user is recognized as a member right away.
      try {
        const communityAgent = await createCommunityAgent(db, did);
        await communityAgent.api.com.atproto.repo.createRecord({
          repo: did,
          collection: 'community.opensocial.membershipProof',
          record: {
            $type: 'community.opensocial.membershipProof',
            memberDid: user_did,
            confirmedAt: new Date().toISOString(),
          },
        });
      } catch (proofErr) {
        console.error('Failed to create membershipProof:', proofErr);
        // Don't block the join — the proof can be created later
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

  // List members (admin only). Supports ?search= DID filter and ?admin_did= for auth.
  router.get('/:did/members', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;
    const adminDid = req.query.admin_did as string | undefined;
    const search = req.query.search as string | undefined;
    const publicMode = req.query.public === 'true';

    // Public mode: return member list without admin auth (for membership checks)
    if (publicMode) {
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

        // List all membershipProof records (paginated)
        let cursor: string | undefined;
        const allProofs: any[] = [];
        do {
          const response = await communityAgent.api.com.atproto.repo.listRecords({
            repo: did,
            collection: 'community.opensocial.membershipProof',
            limit: 100,
            cursor,
          });
          allProofs.push(...response.data.records);
          cursor = response.data.cursor;
        } while (cursor);

        // Get admins list
        let admins: any[] = [];
        try {
          const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
            repo: did,
            collection: 'community.opensocial.admins',
            rkey: 'self',
          });
          admins = (adminsResponse.data.value as any).admins || [];
        } catch {
          // No admins record yet
        }

        let members = allProofs.map((record: any) => ({
          uri: record.uri,
          did: record.value.memberDid || null,
          confirmedAt: record.value.confirmedAt || null,
          isAdmin: record.value.memberDid
            ? isAdminInList(record.value.memberDid, admins)
            : false,
        }));

        // Filter by DID search
        if (search) {
          members = members.filter(
            (m) => m.did && m.did.toLowerCase().includes(search.toLowerCase())
          );
        }

        return res.json({ members, total: members.length });
      } catch (error) {
        console.error('Error fetching members (public):', error);
        return res.status(500).json({ error: 'Failed to fetch members' });
      }
    }

    if (!adminDid) {
      return res.status(400).json({ error: 'admin_did query parameter is required' });
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

      // Verify caller is an admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(adminDid, admins)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // List all membershipProof records (paginated)
      let cursor: string | undefined;
      const allProofs: any[] = [];
      do {
        const response = await communityAgent.api.com.atproto.repo.listRecords({
          repo: did,
          collection: 'community.opensocial.membershipProof',
          limit: 100,
          cursor,
        });
        allProofs.push(...response.data.records);
        cursor = response.data.cursor;
      } while (cursor);

      // Build member list
      let members = allProofs.map((record: any) => ({
        uri: record.uri,
        did: record.value.memberDid || null,
        cid: record.value.cid,
        confirmedAt: record.value.confirmedAt || null,
        isAdmin: record.value.memberDid
          ? isAdminInList(record.value.memberDid, admins)
          : false,
      }));

      // Filter by DID search
      if (search) {
        members = members.filter(
          (m) => m.did && m.did.toLowerCase().includes(search.toLowerCase())
        );
      }

      res.json({ members, total: members.length });
    } catch (error) {
      console.error('Error fetching members:', error);
      res.status(500).json({ error: 'Failed to fetch members' });
    }
  });

  // Promote a member to admin (API key auth)
  router.post('/:did/members/:memberDid/admin', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did, memberDid: rawMemberDid } = req.params;
    const memberDid = decodeURIComponent(rawMemberDid);
    const { admin_did } = req.body;

    if (!admin_did) {
      return res.status(400).json({ error: 'admin_did is required in request body' });
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

      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(admin_did, admins)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      if (isAdminInList(memberDid, admins)) {
        return res.status(409).json({ error: 'Member is already an admin.' });
      }

      // Verify the member exists in this community
      let cursor: string | undefined;
      let found = false;
      do {
        const response = await communityAgent.api.com.atproto.repo.listRecords({
          repo: did,
          collection: 'community.opensocial.membershipProof',
          limit: 100,
          cursor,
        });
        found = response.data.records.some(
          (r: any) => r.value.memberDid === memberDid
        );
        cursor = response.data.cursor;
      } while (cursor && !found);

      if (!found) {
        return res.status(404).json({ error: 'Member not found in this community.' });
      }

      const updatedAdmins = normalizeAdmins(admins);
      updatedAdmins.push({ did: memberDid, addedAt: new Date().toISOString() });

      await communityAgent.api.com.atproto.repo.putRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
        record: {
          $type: 'community.opensocial.admins',
          admins: updatedAdmins,
        },
      });

      res.json({ success: true, admins: updatedAdmins });
    } catch (error) {
      console.error('Error promoting member to admin:', error);
      res.status(500).json({ error: 'Failed to promote member to admin' });
    }
  });

  // Demote an admin (cannot demote the original group creator) (API key auth)
  router.delete('/:did/members/:memberDid/admin', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did, memberDid: rawMemberDid } = req.params;
    const memberDid = decodeURIComponent(rawMemberDid);
    const { admin_did } = req.body;

    if (!admin_did) {
      return res.status(400).json({ error: 'admin_did is required in request body' });
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

      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(admin_did, admins)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // Protect the original group creator
      const originalAdminDid = getOriginalAdminDid(admins);
      if (memberDid === originalAdminDid) {
        return res.status(403).json({
          error: 'Cannot demote the original group creator.',
        });
      }

      if (!isAdminInList(memberDid, admins)) {
        return res.status(404).json({ error: 'Member is not an admin.' });
      }

      const updatedAdmins = normalizeAdmins(admins).filter(
        (a) => a.did !== memberDid
      );

      await communityAgent.api.com.atproto.repo.putRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
        record: {
          $type: 'community.opensocial.admins',
          admins: updatedAdmins,
        },
      });

      res.json({ success: true, admins: updatedAdmins });
    } catch (error) {
      console.error('Error demoting admin:', error);
      res.status(500).json({ error: 'Failed to demote admin' });
    }
  });

  // Remove a member from the group by deleting their membershipProof (API key auth)
  router.delete('/:did/members/:memberDid', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did, memberDid: rawMemberDid } = req.params;
    const memberDid = decodeURIComponent(rawMemberDid);
    const { admin_did } = req.body;

    if (!admin_did) {
      return res.status(400).json({ error: 'admin_did is required in request body' });
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

      // Verify caller is an admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(admin_did, admins)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // Prevent removing the original group creator
      const originalAdminDid = getOriginalAdminDid(admins);
      if (memberDid === originalAdminDid) {
        return res.status(403).json({
          error: 'Cannot remove the original group creator.',
        });
      }

      // Find the membershipProof record for this member
      let cursor: string | undefined;
      let memberProof: any = null;
      do {
        const response = await communityAgent.api.com.atproto.repo.listRecords({
          repo: did,
          collection: 'community.opensocial.membershipProof',
          limit: 100,
          cursor,
        });
        memberProof = response.data.records.find(
          (r: any) => r.value.memberDid === memberDid
        );
        cursor = response.data.cursor;
      } while (cursor && !memberProof);

      if (!memberProof) {
        return res.status(404).json({ error: 'Member not found in this community.' });
      }

      // Delete the membershipProof record
      const rkey = memberProof.uri.split('/').pop()!;
      await communityAgent.api.com.atproto.repo.deleteRecord({
        repo: did,
        collection: 'community.opensocial.membershipProof',
        rkey,
      });

      // If the removed member was also an admin, remove them from the admin list
      if (isAdminInList(memberDid, admins)) {
        const updatedAdmins = normalizeAdmins(admins).filter(
          (a) => a.did !== memberDid
        );
        await communityAgent.api.com.atproto.repo.putRecord({
          repo: did,
          collection: 'community.opensocial.admins',
          rkey: 'self',
          record: {
            $type: 'community.opensocial.admins',
            admins: updatedAdmins,
          },
        });
      }

      res.json({
        success: true,
        message: `Member ${memberDid} removed from community. Their membership record remains in their PDS but is no longer verified.`,
      });
    } catch (error) {
      console.error('Error removing member:', error);
      res.status(500).json({ error: 'Failed to remove member' });
    }
  });

  return router;
}
