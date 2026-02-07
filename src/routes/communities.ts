import { Router } from 'express';
import crypto from 'crypto';
import { BskyAgent } from '@atproto/api';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { createVerifyApiKey, AuthenticatedRequest } from '../middleware/auth';
import { getPublicAgent } from '../services/atproto';
import { isAdminInList, normalizeAdmins } from '../lib/adminUtils';
import { encrypt } from '../lib/crypto';

export function createCommunityRouter(db: Kysely<Database>) {
  const router = Router();
  const verifyApiKey = createVerifyApiKey(db);

  // Create a new community
  router.post('/', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { handle, display_name, description, creator_did } = req.body;

    if (!handle || !display_name || !creator_did) {
      return res.status(400).json({
        error: 'Missing required fields: handle, display_name, creator_did',
      });
    }

    if (!handle.endsWith('.opensocial.community')) {
      return res.status(400).json({
        error: 'Handle must end with .opensocial.community',
      });
    }

    const pdsHost = process.env.PDS_HOSTNAME || 'opensocial.community';
    const accountPassword = crypto.randomBytes(32).toString('hex');

    try {
      // Create account on PDS via API
      console.log(`Creating PDS account for ${handle}...`);

      const createResponse = await fetch(`https://${pdsHost}/xrpc/com.atproto.server.createAccount`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: `${handle.split('.')[0]}@opensocial.community`,
          handle: handle,
          password: accountPassword,
        }),
      });

      if (!createResponse.ok) {
        const error = await createResponse.json();
        console.error('PDS account creation failed:', error);
        return res.status(500).json({
          error: 'Failed to create PDS account',
          details: (error as any).message || 'Unknown error',
        });
      }

      const accountData = await createResponse.json() as { did: string; handle: string };
      const did = accountData.did;

      console.log(`Created community account with DID: ${did}`);

      // Wait a moment for account to be fully ready
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Login to get agent
      const agent = new BskyAgent({ service: `https://${pdsHost}` });
      await agent.login({
        identifier: handle,
        password: accountPassword,
      });

      // Fetch creator's Bluesky profile to get avatar
      let avatarBlob = undefined;
      try {
        const publicAgent = new BskyAgent({ service: 'https://public.api.bsky.app' });
        const creatorProfile = await publicAgent.getProfile({ actor: creator_did });

        if (creatorProfile.data.avatar) {
          const avatarResponse = await fetch(creatorProfile.data.avatar);
          if (avatarResponse.ok) {
            const avatarBuffer = await avatarResponse.arrayBuffer();
            const avatarUint8 = new Uint8Array(avatarBuffer);

            const uploadResponse = await agent.uploadBlob(avatarUint8, {
              encoding: avatarResponse.headers.get('content-type') || 'image/jpeg',
            });
            avatarBlob = uploadResponse.data.blob;
            console.log('Avatar uploaded successfully');
          }
        }
      } catch (error) {
        console.warn('Could not fetch/upload avatar from creator profile:', error);
        // Continue without avatar
      }

      // Create profile record
      const profileRecord: any = {
        $type: 'community.opensocial.profile',
        displayName: display_name,
        description: description || '',
        createdAt: new Date().toISOString(),
      };

      if (avatarBlob) {
        profileRecord.avatar = avatarBlob;
      }

      await agent.com.atproto.repo.putRecord({
        repo: did,
        collection: 'community.opensocial.profile',
        rkey: 'self',
        record: profileRecord,
      });

      // Create admins record
      await agent.com.atproto.repo.putRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
        record: {
          $type: 'community.opensocial.admins',
          admins: [
            {
              did: creator_did,
              permissions: ['edit_profile', 'manage_admins', 'moderate', 'post'],
              addedAt: new Date().toISOString(),
            },
          ],
        },
      });

      // Store in database
      const community = await db
        .insertInto('communities')
        .values({
          did,
          handle,
          display_name: display_name,
          pds_host: pdsHost,
          app_password: encrypt(accountPassword),
        })
        .returningAll()
        .executeTakeFirstOrThrow();

      res.json({
        community: {
          did,
          handle,
          display_name,
          pds_host: pdsHost,
          created_at: community.created_at,
        },
        is_admin: true,
      });
    } catch (error: any) {
      console.error('Error creating community:', error);
      res.status(500).json({
        error: 'Failed to create community',
        details: error.message,
      });
    }
  });

  // List communities
  router.get('/', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { user_did } = req.query;

    try {
      const communities = await db
        .selectFrom('communities')
        .select(['did', 'handle', 'display_name', 'pds_host', 'created_at'])
        .orderBy('created_at', 'desc')
        .execute();

      const result = await Promise.all(
        communities.map(async (community) => {
          let is_admin = false;
          let communityType = 'open';

          try {
            const agent = await getPublicAgent(community.pds_host);

            // Fetch profile to get community type
            try {
              const profileRecord = await agent.com.atproto.repo.getRecord({
                repo: community.did,
                collection: 'community.opensocial.profile',
                rkey: 'self',
              });
              const profile = profileRecord.data.value as any;
              communityType = profile.type || 'open';
            } catch (error) {
              // Profile fetch failed — default to open
            }

            if (user_did) {
              try {
                const adminRecord = await agent.com.atproto.repo.getRecord({
                  repo: community.did,
                  collection: 'community.opensocial.admins',
                  rkey: 'self',
                });

                const admins = (adminRecord.data.value as any).admins || [];
                is_admin = isAdminInList(user_did as string, admins);
              } catch (error) {
                console.error(`Error checking admin status for ${community.handle}`);
              }
            }
          } catch (error) {
            console.error(`Error fetching data for ${community.handle}`);
          }

          return { ...community, is_admin, type: communityType };
        })
      );

      res.json({ communities: result });
    } catch (error) {
      console.error('Error fetching communities:', error);
      res.status(500).json({ error: 'Failed to fetch communities' });
    }
  });

  // Get single community with full profile
  router.get('/:did', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;
    const { user_did } = req.query;

    try {
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const agent = await getPublicAgent(community.pds_host);

      // Fetch profile
      const profileRecord = await agent.com.atproto.repo.getRecord({
        repo: community.did,
        collection: 'community.opensocial.profile',
        rkey: 'self',
      });

      // Fetch admins
      const adminRecord = await agent.com.atproto.repo.getRecord({
        repo: community.did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const profile = profileRecord.data.value as any;
      const admins = (adminRecord.data.value as any).admins || [];
      const is_admin = user_did
        ? admins.some((admin: any) => admin.did === user_did)
        : false;

      res.json({
        community: {
          did: community.did,
          handle: community.handle,
          pds_host: community.pds_host,
          display_name: profile.displayName,
          description: profile.description,
          guidelines: profile.guidelines,
          type: profile.type || 'open',
          admins,
          created_at: profile.createdAt,
        },
        is_admin,
      });
    } catch (error) {
      console.error('Error fetching community:', error);
      res.status(500).json({ error: 'Failed to fetch community' });
    }
  });

  // Delete a community
  router.delete('/:did', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const { did } = req.params;
    const { user_did } = req.body;

    if (!user_did) {
      return res.status(400).json({
        error: 'Missing required field: user_did',
      });
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

      const agent = await getPublicAgent(community.pds_host);

      // Fetch admins to verify permissions
      const adminRecord = await agent.com.atproto.repo.getRecord({
        repo: community.did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminRecord.data.value as any).admins || [];

      // Check if user is an admin
      const isAdmin = isAdminInList(user_did, admins);
      if (!isAdmin) {
        return res.status(403).json({
          error: 'Only admins can delete a community',
        });
      }

      // Check if there's only one admin
      if (admins.length > 1) {
        return res.status(403).json({
          error: 'Community can only be deleted when there is a single admin',
        });
      }

      // Delete from database
      await db
        .deleteFrom('communities')
        .where('did', '=', did)
        .execute();

      res.json({
        success: true,
        message: 'Community deleted successfully',
      });
    } catch (error) {
      console.error('Error deleting community:', error);
      res.status(500).json({ error: 'Failed to delete community' });
    }
  });

  return router;
}
