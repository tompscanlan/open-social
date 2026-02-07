#!/usr/bin/env tsx
/**
 * clearOldGroupRecords.ts — Delete all old community.opensocial.{list,listitem,
 * listitem.status,segment,post,reaction,membershipProof} records from community PDS repos.
 *
 * These collections were moved from the community.opensocial namespace to
 * app.collectivesocial.group.* so that Collective-specific domain records are
 * cleanly separated from the generic OpenSocial community infrastructure records.
 *
 * The old opensocial lexicons for these types have been removed; this script
 * cleans up any records that were written under the old collection names.
 *
 * Usage:
 *   # Process all communities from the database:
 *   npx tsx scripts/clearOldGroupRecords.ts [--dry-run]
 *
 *   # Process a single community by DID + handle + password (no DB needed):
 *   npx tsx scripts/clearOldGroupRecords.ts --did <did> --handle <handle> --password <app-password> [--pds <host>] [--dry-run]
 *
 * Flags:
 *   --dry-run     Show what would be deleted without actually deleting
 *   --did         Community DID (for standalone mode)
 *   --handle      Community handle (for standalone mode)
 *   --password    Community app password (for standalone mode)
 *   --pds         PDS hostname (default: bsky.social)
 */

import dotenv from 'dotenv';
import { BskyAgent } from '@atproto/api';
import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import { decryptIfNeeded } from '../src/lib/crypto';

dotenv.config();

/**
 * The old collection names that should be purged from community PDS repos.
 * Order matters: delete leaf records (reactions, posts) before parents (list).
 */
const OLD_COLLECTIONS = [
  'community.opensocial.reaction',
  'community.opensocial.post',
  'community.opensocial.segment',
  'community.opensocial.listitem.status',
  'community.opensocial.listitem',
  'community.opensocial.list',
  'community.opensocial.membershipProof',
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function pdsServiceUrl(pdsHost: string): string {
  if (pdsHost.startsWith('http://') || pdsHost.startsWith('https://')) {
    return pdsHost;
  }
  return `https://${pdsHost}`;
}

async function listRecords(
  agent: BskyAgent,
  repo: string,
  collection: string
): Promise<{ uri: string; rkey: string }[]> {
  const records: { uri: string; rkey: string }[] = [];
  let cursor: string | undefined;

  do {
    const res = await agent.com.atproto.repo.listRecords({
      repo,
      collection,
      limit: 100,
      cursor,
    });

    for (const rec of res.data.records) {
      const rkey = rec.uri.split('/').pop()!;
      records.push({ uri: rec.uri, rkey });
    }

    cursor = res.data.cursor;
  } while (cursor);

  return records;
}

async function deleteRecord(
  agent: BskyAgent,
  repo: string,
  collection: string,
  rkey: string,
  dryRun: boolean
): Promise<void> {
  if (dryRun) {
    console.log(`    [DRY RUN] Would delete ${collection}/${rkey}`);
    return;
  }

  await agent.com.atproto.repo.deleteRecord({ repo, collection, rkey });
  console.log(`    ✅ Deleted ${collection}/${rkey}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

function getArg(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  if (idx === -1 || idx + 1 >= process.argv.length) return undefined;
  return process.argv[idx + 1];
}

async function processCommunity(
  did: string,
  handle: string,
  pdsHost: string,
  password: string,
  dryRun: boolean
): Promise<{ deleted: number; errored: boolean }> {
  console.log(`\n══════════════════════════════════════════════════════`);
  console.log(`Community: ${handle} (${did})`);
  console.log(`PDS: ${pdsHost}`);
  console.log(`══════════════════════════════════════════════════════`);

  try {
    const agent = new BskyAgent({ service: pdsServiceUrl(pdsHost) });
    await agent.login({ identifier: handle, password });
    console.log('🔑 Authenticated.\n');

    let deleted = 0;
    for (const collection of OLD_COLLECTIONS) {
      console.log(`  ── ${collection} ──`);
      const records = await listRecords(agent, did, collection);

      if (records.length === 0) {
        console.log('    (no records)');
        continue;
      }

      console.log(`    Found ${records.length} record(s)`);
      for (const rec of records) {
        await deleteRecord(agent, did, collection, rec.rkey, dryRun);
        deleted++;
      }
    }

    console.log(`\n  Summary: ${deleted} old record(s) ${dryRun ? 'would be ' : ''}deleted.`);
    return { deleted, errored: false };
  } catch (err) {
    console.error(
      `\n  ❌ Error processing ${handle}: ${err instanceof Error ? err.message : String(err)}`
    );
    return { deleted: 0, errored: true };
  }
}

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const standaloneMode = process.argv.includes('--did');

  if (dryRun) {
    console.log('🔍 DRY RUN — no records will actually be deleted.\n');
  }

  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  Clear old community.opensocial.* group records from PDS    ║');
  console.log('║  (replaced by app.collectivesocial.group.*)                 ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  if (standaloneMode) {
    // ── Standalone mode: single community via CLI args ──
    const did = getArg('--did');
    const handle = getArg('--handle');
    const password = getArg('--password');
    const pdsHost = getArg('--pds') || 'bsky.social';

    if (!did || !handle || !password) {
      console.error('❌ Standalone mode requires --did, --handle, and --password.');
      console.error('   Example: npx tsx scripts/clearOldGroupRecords.ts --did did:plc:abc --handle my.handle --password app-pass-xxxx');
      process.exit(1);
    }

    const { deleted, errored } = await processCommunity(did, handle, pdsHost, password, dryRun);

    console.log(`\n${errored ? '❌' : '✅'} ${deleted} record(s) ${dryRun ? 'would be ' : ''}deleted.`);
    return;
  }

  // ── Database mode: process all communities ──
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL is not set. Add it to .env or pass it as an env var.');
    console.error('   Or use standalone mode: --did <did> --handle <handle> --password <password>');
    process.exit(1);
  }

  const db = new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({ connectionString: process.env.DATABASE_URL }),
    }),
  });

  console.log('Loading communities from database...\n');

  const communities = await db
    .selectFrom('communities')
    .select(['did', 'handle', 'pds_host', 'app_password'])
    .execute();

  if (communities.length === 0) {
    console.log('No communities found in the database.');
    await db.destroy();
    return;
  }

  console.log(`Found ${communities.length} community/communities.\n`);

  let totalDeleted = 0;
  let communitiesProcessed = 0;
  let communitiesErrored = 0;

  for (const community of communities) {
    const { deleted, errored } = await processCommunity(
      community.did,
      community.handle,
      community.pds_host,
      decryptIfNeeded(community.app_password),
      dryRun
    );
    totalDeleted += deleted;
    if (errored) communitiesErrored++;
    else communitiesProcessed++;
  }

  await db.destroy();

  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  if (dryRun) {
    console.log(`║  🔍 DRY RUN complete.                                       ║`);
  } else {
    console.log(`║  ✅ Migration complete.                                      ║`);
  }
  console.log(`╟──────────────────────────────────────────────────────────────╢`);
  console.log(`║  Communities processed: ${String(communitiesProcessed).padStart(4)}                                ║`);
  if (communitiesErrored > 0) {
    console.log(`║  Communities errored:   ${String(communitiesErrored).padStart(4)}                                ║`);
  }
  console.log(`║  Old records deleted:   ${String(totalDeleted).padStart(4)}                                ║`);
  console.log(`╚══════════════════════════════════════════════════════════════╝\n`);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
