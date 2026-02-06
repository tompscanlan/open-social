import { BskyAgent, AtpAgent } from '@atproto/api';
import type { Kysely } from 'kysely';
import type { Database } from '../db';

export async function createCommunityAgent(db: Kysely<Database>, did: string): Promise<BskyAgent> {
  const community = await db
    .selectFrom('communities')
    .select(['handle', 'pds_host', 'app_password'])
    .where('did', '=', did)
    .executeTakeFirst();

  if (!community) {
    throw new Error('Community not found');
  }

  const agent = new BskyAgent({ service: `https://${community.pds_host}` });
  
  await agent.login({
    identifier: community.handle,
    password: community.app_password,
  });

  return agent;
}

export async function getPublicAgent(pdsHost: string): Promise<AtpAgent> {
  return new AtpAgent({ service: `https://${pdsHost}` });
}
