import { Agent, BskyAgent } from '@atproto/api';
import express, { Request, Response } from 'express';
import { getIronSession } from 'iron-session';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { NodeOAuthClient } from '@atproto/oauth-client-node';
import crypto from 'crypto';
import multer from 'multer';
import { config } from '../config';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { ensureServiceUrl } from '../services/atproto';
import { isAdminInList, getOriginalAdminDid, normalizeAdmins } from '../lib/adminUtils';
import { createCommunityAgent } from '../services/atproto';

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 1024 * 1024, // 1MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  },
});

interface CommunityProfile {
  displayName: string;
  description?: string;
  type?: 'open' | 'admin-approved' | 'private';
  avatar?: string | { $type: string; ref: { $link: string }; mimeType: string };
}

interface MembershipRecord {
  community: string; // DID of the community
  role: string; // member, admin, moderator, etc.
  since: string; // ISO timestamp
}

interface MembershipProofRecord {
  cid: string; // CID of the user's membership record
}

// Helper to convert blob reference to CDN URL
function blobToUrl(blob: any, did: string, pdsHost: string): string | undefined {
  if (!blob) return undefined;
  if (typeof blob === 'string') return blob;
  
  const serviceUrl = ensureServiceUrl(pdsHost);

  // Handle BlobRef object from @atproto/api
  if (blob.ref) {
    const cid = typeof blob.ref === 'string' ? blob.ref : blob.ref.toString();
    return `${serviceUrl}/xrpc/com.atproto.sync.getBlob?did=${did}&cid=${cid}`;
  }
  
  // Handle plain blob object with $type
  if (blob.$type === 'blob' && blob.ref?.$link) {
    return `${serviceUrl}/xrpc/com.atproto.sync.getBlob?did=${did}&cid=${blob.ref.$link}`;
  }
  
  return undefined;
}

/**
 * Fetch the Bluesky profile avatar for a DID as a fallback
 * when no custom community avatar is set.
 */
async function fetchBlueskyAvatar(did: string): Promise<string | undefined> {
  try {
    const publicAgent = new BskyAgent({ service: 'https://public.api.bsky.app' });
    const profile = await publicAgent.getProfile({ actor: did });
    return profile.data.avatar || undefined;
  } catch (err) {
    console.warn(`Could not fetch Bluesky avatar for ${did}:`, err instanceof Error ? err.message : err);
    return undefined;
  }
}

function ifString(val: unknown): string | undefined {
  return typeof val === 'string' && val.length > 0 ? val : undefined;
}

type Session = { did?: string };

const MAX_AGE = config.nodeEnv === 'production' ? 60 : 300;

// Consistent session options for all session operations
const sessionOptions = {
  cookieName: 'sid',
  password: config.cookieSecret,
  cookieOptions: {
    secure: config.nodeEnv === 'production',
    sameSite: 'lax' as const,
    httpOnly: true,
    path: '/',
  },
};

// Helper function to get the Atproto Agent for the active session
async function getSessionAgent(
  req: IncomingMessage,
  res: ServerResponse,
  oauthClient: NodeOAuthClient
) {
  res.setHeader('Vary', 'Cookie');

  const session = await getIronSession<Session>(req, res, sessionOptions);
  
  if (!session.did) {
    console.log('No DID in session');
    return null;
  }

  res.setHeader('cache-control', `max-age=${MAX_AGE}, private`);

  try {
    const oauthSession = await oauthClient.restore(session.did);
    return oauthSession ? new Agent(oauthSession) : null;
  } catch (err) {
    console.warn('OAuth restore failed:', err);
    await session.destroy();
    return null;
  }
}

export function createAuthRouter(oauthClient: NodeOAuthClient, db: Kysely<Database>) {
  const router = express.Router();

  // OAuth metadata
  router.get('/oauth-client-metadata.json', (req: Request, res: Response) => {
    res.setHeader('cache-control', `max-age=${MAX_AGE}, public`);
    res.json(oauthClient.clientMetadata);
  });

  // Public keys
  router.get('/.well-known/jwks.json', (req: Request, res: Response) => {
    res.setHeader('cache-control', `max-age=${MAX_AGE}, public`);
    res.json(oauthClient.jwks);
  });

  // OAuth callback to complete session creation
  router.get('/oauth/callback', async (req: Request, res: Response) => {
    res.setHeader('cache-control', 'no-store');

    const params = new URLSearchParams(req.originalUrl.split('?')[1]);
    
    try {
      // Load the session cookie
      const session = await getIronSession<Session>(req, res, sessionOptions);

      // If the user is already signed in, destroy the old credentials
      if (session.did) {
        try {
          const oauthSession = await oauthClient.restore(session.did);
          if (oauthSession) oauthSession.signOut();
        } catch (err) {
          console.warn('OAuth restore failed:', err);
        }
      }

      // Complete the OAuth flow
      const oauth = await oauthClient.callback(params);

      // Update the session cookie
      session.did = oauth.session.did;

      await session.save();
    } catch (err) {
      console.error('OAuth callback failed:', err);
    }

    // Redirect back to the frontend
    const redirectUrl = config.nodeEnv === 'production'
      ? config.serviceUrl || 'http://127.0.0.1:5174'
      : 'http://127.0.0.1:5174';
    return res.redirect(redirectUrl);
  });

  // Login handler
  router.post('/login', express.urlencoded({ extended: true }), async (req: Request, res: Response) => {
    res.setHeader('cache-control', 'no-store');

    try {
      // Validate input: can be a handle, a DID or a service URL (PDS).
      const input = ifString(req.body.input);
      if (!input) {
        throw new Error('Invalid input');
      }

      // Initiate the OAuth flow
      const url = await oauthClient.authorize(input, {
        scope: 'atproto transition:generic',
      });

      res.redirect(url.toString());
    } catch (err) {
      console.error('OAuth authorize failed:', err);
      const error = err instanceof Error ? err.message : 'unexpected error';
      return res.type('json').send({ error });
    }
  });

  // Logout handler
  router.post('/logout', async (req: Request, res: Response) => {
    res.setHeader('cache-control', 'no-store');

    const session = await getIronSession<Session>(req, res, sessionOptions);

    // Revoke credentials on the server
    if (session.did) {
      try {
        const oauthSession = await oauthClient.restore(session.did);
        if (oauthSession) await oauthSession.signOut();
      } catch (err) {
        console.warn('Failed to revoke credentials:', err);
      }
    }

    session.destroy();

    return res.json({ success: true });
  });

  // Get current user
  router.get('/users/me', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const profile = await agent.getProfile({ actor: agent.assertDid });
      
      return res.json({
        did: agent.assertDid,
        handle: profile.data.handle,
        displayName: profile.data.displayName,
        avatar: profile.data.avatar,
        description: profile.data.description,
      });
    } catch (err) {
      console.error('Failed to get user:', err);
      return res.status(500).json({ error: 'Failed to get user' });
    }
  });

  // Get user's community memberships
  router.get('/users/me/memberships', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      // Fetch user's membership records
      const membershipsResponse = await agent.api.com.atproto.repo.listRecords({
        repo: agent.assertDid,
        collection: 'community.opensocial.membership',
      });

      // Fetch details for each community
      const memberships = await Promise.all(
        membershipsResponse.data.records.map(async (record: any) => {
          try {
            const membershipValue = record.value as MembershipRecord;
            const communityDid = membershipValue.community;
            const membershipUri = record.uri;

            // Get community credentials from database
            const community = await db
              .selectFrom('communities')
              .selectAll()
              .where('did', '=', communityDid)
              .executeTakeFirst();

            if (!community) {
              console.warn(`Community ${communityDid} not found in database`);
              return null;
            }

            // Create agent for the community
            const communityAgent = new BskyAgent({ service: ensureServiceUrl(community.pds_host) });
            await communityAgent.login({
              identifier: community.handle,
              password: community.app_password,
            });

            // Fetch community profile using the community's own agent
            try {
              const profileResponse = await communityAgent.api.com.atproto.repo.getRecord({
                repo: communityDid,
                collection: 'community.opensocial.profile',
                rkey: 'self',
              });

              const profileValue = profileResponse.data.value as CommunityProfile;

              const avatarUrl = blobToUrl(profileValue.avatar, communityDid, community.pds_host)
                || await fetchBlueskyAvatar(communityDid);

              // Check if community has confirmed this membership via membershipProof
              const proofsResponse = await communityAgent.api.com.atproto.repo.listRecords({
                repo: communityDid,
                collection: 'community.opensocial.membershipProof',
              });

              // Get the membership record details to compare CID
              const membershipRecordResponse = await agent.api.com.atproto.repo.getRecord({
                repo: agent.assertDid,
                collection: 'community.opensocial.membership',
                rkey: record.uri.split('/').pop()!,
              });

              const isConfirmed = proofsResponse.data.records.some(
                (proof: any) => {
                  const proofValue = proof.value as MembershipProofRecord;
                  // Check if the proof's CID matches the membership record's CID
                  return proofValue.cid === membershipRecordResponse.data.cid;
                }
              );

              return {
                uri: record.uri,
                cid: record.cid,
                communityDid,
                joinedAt: membershipValue.since,
                role: membershipValue.role,
                status: isConfirmed ? 'active' : 'pending',
                community: {
                  did: communityDid,
                  displayName: profileValue.displayName,
                  description: profileValue.description,
                  avatar: avatarUrl,
                },
              };
            } catch (profileErr) {
              console.warn(`Failed to fetch profile for community ${communityDid}:`, profileErr instanceof Error ? profileErr.message : profileErr);
              return null;
            }
          } catch (err) {
            console.error(`Failed to process membership record:`, err);
            return null;
          }
        })
      );

      // Filter out null entries (failed fetches)
      const validMemberships = memberships.filter((m): m is NonNullable<typeof m> => m !== null);

      return res.json({ memberships: validMemberships });
    } catch (err) {
      console.error('Failed to get memberships:', err);
      return res.status(500).json({ error: 'Failed to get memberships' });
    }
  });

  // Create a new community
  router.post('/users/me/communities', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const { type, name, displayName, description, did: existingDid, appPassword } = req.body;

      if (!displayName) {
        return res.status(400).json({ error: 'displayName is required' });
      }

      let communityDid: string;
      let communityHandle: string;
      let communityAgent: Agent;

      if (type === 'new') {
        // Create new community on opensocial.community PDS
        if (!name) {
          return res.status(400).json({ error: 'name is required for new communities' });
        }

        const handle = `${name}.opensocial.community`;
        const pdsHost = config.pdsUrl || 'https://opensocial.community';
        const accountPassword = crypto.randomBytes(32).toString('hex');

        // Create account on PDS
        const createResponse = await fetch(`${pdsHost}/xrpc/com.atproto.server.createAccount`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: `${name}@opensocial.community`,
            handle: handle,
            password: accountPassword,
          }),
        });

        if (!createResponse.ok) {
          const error = await createResponse.json() as { message?: string };
          console.error('PDS account creation failed:', error);
          return res.status(500).json({ 
            error: 'Failed to create PDS account',
            details: error.message || 'Unknown error'
          });
        }

        const accountData = await createResponse.json() as { did: string; handle: string };
        communityDid = accountData.did;
        communityHandle = handle;

        // Wait for account to be ready
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Login as the community
        const bskyAgent = new BskyAgent({ service: pdsHost });
        await bskyAgent.login({
          identifier: handle,
          password: accountPassword,
        });
        communityAgent = bskyAgent;

        // Store password in database (encrypted in production!)
        await db
          .insertInto('communities')
          .values({
            did: communityDid,
            handle: communityHandle,
            display_name: displayName,
            pds_host: pdsHost,
            app_password: accountPassword,
            created_at: new Date(),
          })
          .execute();

      } else if (type === 'existing') {
        // Use existing DID with app password
        if (!existingDid || !appPassword) {
          return res.status(400).json({ error: 'did and appPassword are required for existing communities' });
        }

        communityDid = existingDid;

        // Resolve DID to get handle and PDS
        let pdsHost = 'https://bsky.social';
        try {
          const profile = await agent.getProfile({ actor: existingDid });
          communityHandle = profile.data.handle || existingDid;
        } catch (e) {
          console.warn('Could not resolve handle, using DID as fallback');
          communityHandle = existingDid;
        }

        // Login with app password
        const bskyAgent = new BskyAgent({ service: pdsHost });
        await bskyAgent.login({
          identifier: existingDid,
          password: appPassword,
        });
        communityAgent = bskyAgent;

        // Store in database
        await db
          .insertInto('communities')
          .values({
            did: communityDid,
            handle: communityHandle,
            display_name: displayName,
            pds_host: pdsHost,
            app_password: appPassword,
            created_at: new Date(),
          })
          .execute();

      } else {
        return res.status(400).json({ error: 'Invalid type. Must be "new" or "existing"' });
      }

      // Create community profile
      try {
        await communityAgent.api.com.atproto.repo.putRecord({
          repo: communityDid,
          collection: 'community.opensocial.profile',
          rkey: 'self',
          record: {
            $type: 'community.opensocial.profile',
            displayName,
            description: description || '',
            type: 'open', // Default to open community
            createdAt: new Date().toISOString(),
          },
        });
      } catch (err) {
        console.error('Failed to create profile record:', err);
        return res.status(500).json({ 
          error: 'Failed to create community profile',
          details: err instanceof Error ? err.message : 'Unknown error'
        });
      }

      // Create admin list with creator as first admin
      try {
        await communityAgent.api.com.atproto.repo.putRecord({
          repo: communityDid,
          collection: 'community.opensocial.admins',
          rkey: 'self',
          record: {
            $type: 'community.opensocial.admins',
            admins: [{ did: agent.assertDid, addedAt: new Date().toISOString() }],
          },
        });
      } catch (err) {
        console.error('Failed to create admins list:', err);
        return res.status(500).json({ 
          error: 'Failed to create admins list',
          details: err instanceof Error ? err.message : 'Unknown error'
        });
      }

      // Create membership record in user's repo
      const membershipRecord = await agent.api.com.atproto.repo.createRecord({
        repo: agent.assertDid,
        collection: 'community.opensocial.membership',
        record: {
          $type: 'community.opensocial.membership',
          community: communityDid,
          role: 'admin', // Creator is admin
          since: new Date().toISOString(),
        },
      });

      // Create membershipProof in community's repo using the membership record's CID
      await communityAgent.api.com.atproto.repo.createRecord({
        repo: communityDid,
        collection: 'community.opensocial.membershipProof',
        record: {
          $type: 'community.opensocial.membershipProof',
          memberDid: agent.assertDid,
          cid: membershipRecord.data.cid,
          confirmedAt: new Date().toISOString(),
        },
      });

      return res.json({
        success: true,
        community: {
          did: communityDid,
          handle: communityHandle,
          displayName,
          description,
        },
      });
    } catch (err) {
      console.error('Failed to create community:', err);
      return res.status(500).json({ 
        error: 'Failed to create community',
        details: err instanceof Error ? err.message : 'Unknown error'
      });
    }
  });

  // Get community details
  router.get('/communities/:did', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const communityDid = decodeURIComponent(req.params.did);

      // Get community from database
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      // Create community agent
      const communityAgent = new BskyAgent({ service: ensureServiceUrl(community.pds_host) });
      await communityAgent.login({
        identifier: community.handle,
        password: community.app_password,
      });

      // Fetch community profile
      const profileResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.profile',
        rkey: 'self',
      });

      const profileValue = profileResponse.data.value as CommunityProfile;

      const avatarUrl = blobToUrl(profileValue.avatar, communityDid, community.pds_host)
        || await fetchBlueskyAvatar(communityDid);

      // Count members (membership proofs)
      const proofsResponse = await communityAgent.api.com.atproto.repo.listRecords({
        repo: communityDid,
        collection: 'community.opensocial.membershipProof',
      });

      const memberCount = proofsResponse.data.records.length;

      // Check if user is admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const adminsValue = (adminsResponse.data.value as any).admins || [];
      const isAdmin = isAdminInList(agent.assertDid, adminsValue);

      // Get user's role from their membership record
      const membershipResponse = await agent.api.com.atproto.repo.listRecords({
        repo: agent.assertDid,
        collection: 'community.opensocial.membership',
      });

      const userMembership = membershipResponse.data.records.find((record: any) => {
        const value = record.value as MembershipRecord;
        return value.community === communityDid;
      });

      const userRole = userMembership ? (userMembership.value as MembershipRecord).role : undefined;

      return res.json({
        community: {
          did: communityDid,
          displayName: profileValue.displayName,
          description: profileValue.description,
          type: profileValue.type || 'open', // Default to 'open' if not set
          avatar: avatarUrl,
        },
        memberCount,
        isAdmin,
        userRole,
      });
    } catch (err) {
      console.error('Failed to get community details:', err);
      return res.status(500).json({ 
        error: 'Failed to get community details',
        details: err instanceof Error ? err.message : 'Unknown error'
      });
    }
  });

  // Upload community avatar
  router.post('/communities/:did/avatar', upload.single('avatar'), async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const communityDid = decodeURIComponent(req.params.did);

      // Get community from database
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      // Check if user is admin
      const communityAgent = new BskyAgent({ service: ensureServiceUrl(community.pds_host) });
      await communityAgent.login({
        identifier: community.handle,
        password: community.app_password,
      });

      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const adminsListAvatar = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(agent.assertDid, adminsListAvatar)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // Get uploaded file from multipart form data
      const file = req.file;
      if (!file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      // Upload blob to community's PDS
      const uploadResponse = await communityAgent.api.com.atproto.repo.uploadBlob(file.buffer, {
        encoding: file.mimetype,
      });

      const blobRef = uploadResponse.data.blob;

      // Update community profile with new avatar
      const profileResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.profile',
        rkey: 'self',
      });

      const currentProfile = profileResponse.data.value as CommunityProfile;

      await communityAgent.api.com.atproto.repo.putRecord({
        repo: communityDid,
        collection: 'community.opensocial.profile',
        rkey: 'self',
        record: {
          ...currentProfile,
          $type: 'community.opensocial.profile',
          avatar: blobRef,
        },
      });

      return res.json({ success: true, avatar: blobRef });
    } catch (err) {
      console.error('Failed to upload avatar:', err);
      return res.status(500).json({ 
        error: 'Failed to upload avatar',
        details: err instanceof Error ? err.message : 'Unknown error'
      });
    }
  });

  // Update community profile (name and description)
  router.put('/communities/:did/profile', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const communityDid = decodeURIComponent(req.params.did);
      const { displayName, description, type } = req.body;

      // Validate input
      if (!displayName || typeof displayName !== 'string' || !displayName.trim()) {
        return res.status(400).json({ error: 'displayName is required' });
      }

      // Validate type if provided
      if (type && !['open', 'admin-approved', 'private'].includes(type)) {
        return res.status(400).json({ error: 'type must be "open", "admin-approved", or "private"' });
      }

      // Get community from database
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      // Create community agent
      const communityAgent = new BskyAgent({ service: ensureServiceUrl(community.pds_host) });
      await communityAgent.login({
        identifier: community.handle,
        password: community.app_password,
      });

      // Check if user is admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const adminsListProfile = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(agent.assertDid, adminsListProfile)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // Get current profile
      const profileResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.profile',
        rkey: 'self',
      });

      const currentProfile = profileResponse.data.value as CommunityProfile;

      // Update profile with new values
      await communityAgent.api.com.atproto.repo.putRecord({
        repo: communityDid,
        collection: 'community.opensocial.profile',
        rkey: 'self',
        record: {
          ...currentProfile,
          $type: 'community.opensocial.profile',
          displayName: displayName.trim(),
          description: description ? description.trim() : '',
          type: type || currentProfile.type || 'open',
        },
      });

      return res.json({ success: true });
    } catch (err) {
      console.error('Failed to update community profile:', err);
      return res.status(500).json({ 
        error: 'Failed to update community profile',
        details: err instanceof Error ? err.message : 'Unknown error'
      });
    }
  });

  // Delete a community
  router.delete('/communities/:did', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const { did } = req.params;
      const userDid = agent.assertDid;

      // Get community credentials from database
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', did)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      // Create agent for the community
      const communityAgent = new BskyAgent({ service: ensureServiceUrl(community.pds_host) });
      await communityAgent.login({
        identifier: community.handle,
        password: community.app_password,
      });

      // Fetch admins to verify permissions
      const adminRecord = await communityAgent.api.com.atproto.repo.getRecord({
        repo: did,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminRecord.data.value as any).admins || [];

      // Check if user is an admin
      if (!isAdminInList(userDid, admins)) {
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

      return res.json({
        success: true,
        message: 'Community deleted successfully',
      });
    } catch (err) {
      console.error('Failed to delete community:', err);
      return res.status(500).json({ 
        error: 'Failed to delete community',
        details: err instanceof Error ? err.message : 'Unknown error'
      });
    }
  });

  // ── Admin member management routes ─────────────────────────────────────

  // List all group members (admin only), with optional ?search= DID filter
  router.get('/communities/:did/members', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const communityDid = decodeURIComponent(req.params.did);
      const search = req.query.search as string | undefined;

      // Get community from database
      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      // Create community agent
      const communityAgent = await createCommunityAgent(db, communityDid);

      // Verify caller is an admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(agent.assertDid, admins)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // List all membershipProof records (paginated)
      let cursor: string | undefined;
      const allProofs: any[] = [];
      do {
        const response = await communityAgent.api.com.atproto.repo.listRecords({
          repo: communityDid,
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

      return res.json({ members, total: members.length });
    } catch (err) {
      console.error('Failed to list members:', err);
      return res.status(500).json({
        error: 'Failed to list members',
        details: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  });

  // Promote a member to admin
  router.post('/communities/:did/members/:memberDid/admin', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const communityDid = decodeURIComponent(req.params.did);
      const memberDid = decodeURIComponent(req.params.memberDid);

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      // Verify caller is an admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(agent.assertDid, admins)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // Check if already an admin
      if (isAdminInList(memberDid, admins)) {
        return res.status(409).json({ error: 'Member is already an admin.' });
      }

      // Verify the member has a membershipProof in this community
      let cursor: string | undefined;
      let found = false;
      do {
        const response = await communityAgent.api.com.atproto.repo.listRecords({
          repo: communityDid,
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

      // Add member to admin list (normalize to canonical format)
      const updatedAdmins = normalizeAdmins(admins);
      updatedAdmins.push({ did: memberDid, addedAt: new Date().toISOString() });

      await communityAgent.api.com.atproto.repo.putRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
        record: {
          $type: 'community.opensocial.admins',
          admins: updatedAdmins,
        },
      });

      return res.json({ success: true, admins: updatedAdmins });
    } catch (err) {
      console.error('Failed to promote member to admin:', err);
      return res.status(500).json({
        error: 'Failed to promote member to admin',
        details: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  });

  // Demote an admin (cannot demote the original group creator)
  router.delete('/communities/:did/members/:memberDid/admin', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const communityDid = decodeURIComponent(req.params.did);
      const memberDid = decodeURIComponent(req.params.memberDid);

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      // Verify caller is an admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(agent.assertDid, admins)) {
        return res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      }

      // Protect the original group creator
      const originalAdminDid = getOriginalAdminDid(admins);
      if (memberDid === originalAdminDid) {
        return res.status(403).json({
          error: 'Cannot demote the original group creator.',
        });
      }

      // Verify the target is actually an admin
      if (!isAdminInList(memberDid, admins)) {
        return res.status(404).json({ error: 'Member is not an admin.' });
      }

      // Remove from admin list
      const updatedAdmins = normalizeAdmins(admins).filter(
        (a) => a.did !== memberDid
      );

      await communityAgent.api.com.atproto.repo.putRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
        record: {
          $type: 'community.opensocial.admins',
          admins: updatedAdmins,
        },
      });

      return res.json({ success: true, admins: updatedAdmins });
    } catch (err) {
      console.error('Failed to demote admin:', err);
      return res.status(500).json({
        error: 'Failed to demote admin',
        details: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  });

  // Remove a member from the group by deleting their membershipProof
  router.delete('/communities/:did/members/:memberDid', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const communityDid = decodeURIComponent(req.params.did);
      const memberDid = decodeURIComponent(req.params.memberDid);

      const community = await db
        .selectFrom('communities')
        .selectAll()
        .where('did', '=', communityDid)
        .executeTakeFirst();

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const communityAgent = await createCommunityAgent(db, communityDid);

      // Verify caller is an admin
      const adminsResponse = await communityAgent.api.com.atproto.repo.getRecord({
        repo: communityDid,
        collection: 'community.opensocial.admins',
        rkey: 'self',
      });

      const admins = (adminsResponse.data.value as any).admins || [];
      if (!isAdminInList(agent.assertDid, admins)) {
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
          repo: communityDid,
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
        repo: communityDid,
        collection: 'community.opensocial.membershipProof',
        rkey,
      });

      // If the removed member was also an admin, remove them from the admin list
      if (isAdminInList(memberDid, admins)) {
        const updatedAdmins = normalizeAdmins(admins).filter(
          (a) => a.did !== memberDid
        );
        await communityAgent.api.com.atproto.repo.putRecord({
          repo: communityDid,
          collection: 'community.opensocial.admins',
          rkey: 'self',
          record: {
            $type: 'community.opensocial.admins',
            admins: updatedAdmins,
          },
        });
      }

      return res.json({
        success: true,
        message: `Member ${memberDid} removed from community. Their membership record remains in their PDS but is no longer verified.`,
      });
    } catch (err) {
      console.error('Failed to remove member:', err);
      return res.status(500).json({
        error: 'Failed to remove member',
        details: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  });

  return router;
}
