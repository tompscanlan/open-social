#!/usr/bin/env tsx
/**
 * clearData.ts — Clear all AT Protocol records for a given DID (user or community).
 *
 * This script will:
 *   - For a community DID (found in the local DB):
 *     1. Delete all community.opensocial.member records (from the community's repo)
 *     2. Delete the community.opensocial.admins record
 *     3. Delete the community.opensocial.profile record
 *     4. Optionally remove the community row from the local database
 *
 *   - For a user DID (not in the DB — treated as a regular user):
 *     1. Delete all community.opensocial.membership records from the user's repo
 *     (Requires an app password; PDS host is auto-resolved from the DID document)
 *
 * Usage:
 *   npx tsx scripts/clearData.ts <did> [--delete-db-row] [--user-pds <host>] [--user-password <app-password>]
 *
 * Examples:
 *   # Clear a community's data (credentials come from the DB):
 *   npx tsx scripts/clearData.ts did:plc:abc123
 *
 *   # Clear a community's data AND remove the DB row:
 *   npx tsx scripts/clearData.ts did:plc:abc123 --delete-db-row
 *
 *   # Clear a user's membership records (PDS auto-resolved):
 *   npx tsx scripts/clearData.ts did:plc:xyz789 --user-password app-pass-xxxx-xxxx
 *
 *   # Clear a user's membership records (explicit PDS override):
 *   npx tsx scripts/clearData.ts did:plc:xyz789 --user-pds bsky.social --user-password app-pass-xxxx-xxxx
 */

import dotenv from 'dotenv';
import { BskyAgent } from '@atproto/api';
import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import type { Database } from '../src/db';
import { decryptIfNeeded } from '../src/lib/crypto';

dotenv.config();

// ── Helpers ──────────────────────────────────────────────────────────────────

function pdsServiceUrl(pdsHost: string): string {
  if (pdsHost.startsWith('http://') || pdsHost.startsWith('https://')) {
    return pdsHost;
  }
  return `https://${pdsHost}`;
}

/**
 * Resolve a DID to its PDS endpoint via plc.directory (for did:plc:)
 * or by fetching the DID document directly (for did:web:).
 */
async function resolvePdsFromDid(did: string): Promise<string> {
  let didDoc: any;

  if (did.startsWith('did:plc:')) {
    const res = await fetch(`https://plc.directory/${did}`);
    if (!res.ok) {
      throw new Error(`Failed to resolve ${did} via plc.directory (HTTP ${res.status})`);
    }
    didDoc = await res.json();
  } else if (did.startsWith('did:web:')) {
    const host = did.replace('did:web:', '');
    const res = await fetch(`https://${host}/.well-known/did.json`);
    if (!res.ok) {
      throw new Error(`Failed to resolve ${did} via did:web (HTTP ${res.status})`);
    }
    didDoc = await res.json();
  } else {
    throw new Error(`Unsupported DID method: ${did}`);
  }

  // Find the atproto_pds service endpoint
  const services = didDoc.service || [];
  const pdsSvc = services.find(
    (s: any) => s.id === '#atproto_pds' || s.type === 'AtprotoPersonalDataServer'
  );

  if (!pdsSvc?.serviceEndpoint) {
    throw new Error(`No PDS service endpoint found in DID document for ${did}`);
  }

  return pdsSvc.serviceEndpoint;
}

function usage(): never {
  console.log(`
Usage:
  npx tsx scripts/clearData.ts <did> [options]

Options:
  --delete-db-row              Also delete the community row from the local DB
  --user-pds <host>            PDS host override (auto-resolved from DID if omitted)
  --user-password <password>   App password for the user DID
  --dry-run                    Show what would be deleted without actually deleting
  --help                       Show this help message
`);
  process.exit(1);
}

function parseArgs(argv: string[]) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('--help')) usage();

  const deleteDbRow = args.includes('--delete-db-row');
  const dryRun = args.includes('--dry-run');

  let userPds: string | undefined;
  let userPassword: string | undefined;

  const pdsIdx = args.indexOf('--user-pds');
  if (pdsIdx !== -1) userPds = args[pdsIdx + 1];

  const pwIdx = args.indexOf('--user-password');
  if (pwIdx !== -1) userPassword = args[pwIdx + 1];

  // Flags that consume a value after them
  const flagsWithValue = new Set(['--user-pds', '--user-password']);
  const bareFlags = new Set(['--delete-db-row', '--dry-run', '--help']);

  // Find the positional DID argument (first arg that isn't a flag or a flag's value)
  let did: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (flagsWithValue.has(args[i])) {
      i++; // skip the flag's value
      continue;
    }
    if (bareFlags.has(args[i])) continue;
    did = args[i];
    break;
  }

  if (!did) {
    console.error('❌ No DID provided.\n');
    usage();
  }

  return { did, deleteDbRow, dryRun, userPds, userPassword };
}

async function listRecords(agent: BskyAgent, repo: string, collection: string) {
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
) {
  if (dryRun) {
    console.log(`  [DRY RUN] Would delete ${collection}/${rkey}`);
    return;
  }

  await agent.com.atproto.repo.deleteRecord({ repo, collection, rkey });
  console.log(`  ✅ Deleted ${collection}/${rkey}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const { did, deleteDbRow, dryRun, userPds, userPassword } = parseArgs(process.argv);

  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL is not set. Add it to .env or pass it as an env var.');
    process.exit(1);
  }

  const db = new Kysely<Database>({
    dialect: new PostgresDialect({
      pool: new Pool({ connectionString: process.env.DATABASE_URL }),
    }),
  });

  if (dryRun) {
    console.log('🔍 DRY RUN — no records will actually be deleted.\n');
  }

  console.log(`Looking up DID: ${did}\n`);

  // Check if this is a community DID
  const community = await db
    .selectFrom('communities')
    .select(['did', 'handle', 'pds_host', 'app_password'])
    .where('did', '=', did)
    .executeTakeFirst();

  if (community) {
    await clearCommunityData(db, community, deleteDbRow, dryRun);
  } else if (userPassword) {
    // Resolve the PDS host from the DID document unless explicitly provided
    let resolvedPds = userPds;
    if (!resolvedPds) {
      console.log('Resolving PDS host from DID document...');
      resolvedPds = await resolvePdsFromDid(did);
      console.log(`Resolved PDS: ${resolvedPds}\n`);
    }
    await clearUserData(did, resolvedPds, userPassword, dryRun);
  } else {
    console.log(`DID ${did} is not a community in the database.`);
    console.log(
      "To clear a user's data, provide --user-password (PDS is auto-resolved).\n"
    );
    console.log('Example:');
    console.log(
      `  npx tsx scripts/clearData.ts ${did} --user-password app-pass-xxxx-xxxx`
    );
    process.exit(1);
  }

  await db.destroy();
  console.log('\n🏁 Done.');
}

// ── Community cleanup ────────────────────────────────────────────────────────

async function clearCommunityData(
  db: Kysely<Database>,
  community: { did: string; handle: string; pds_host: string; app_password: string },
  deleteDbRow: boolean,
  dryRun: boolean
) {
  console.log(`Found community: ${community.handle} (${community.did})`);
  console.log(`PDS host: ${community.pds_host}\n`);

  // Authenticate as the community account
  const agent = new BskyAgent({ service: pdsServiceUrl(community.pds_host) });
  await agent.login({
    identifier: community.handle,
    password: decryptIfNeeded(community.app_password),
  });
  console.log('🔑 Authenticated as community account.\n');

  // 1. Delete all community.opensocial.member records (tid-keyed)
  console.log('── community.opensocial.member ──');
  const members = await listRecords(agent, community.did, 'community.opensocial.member');
  if (members.length === 0) {
    console.log('  No member records found.');
  } else {
    console.log(`  Found ${members.length} member record(s).`);
    for (const rec of members) {
      await deleteRecord(agent, community.did, 'community.opensocial.member', rec.rkey, dryRun);
    }
  }

  // 2. Delete the community.opensocial.admins record
  console.log('\n── community.opensocial.admins ──');
  const admins = await listRecords(agent, community.did, 'community.opensocial.admins');
  if (admins.length === 0) {
    console.log('  No admins record found.');
  } else {
    for (const rec of admins) {
      await deleteRecord(agent, community.did, 'community.opensocial.admins', rec.rkey, dryRun);
    }
  }

  // 3. Delete the community.opensocial.profile record
  console.log('\n── community.opensocial.profile ──');
  const profiles = await listRecords(agent, community.did, 'community.opensocial.profile');
  if (profiles.length === 0) {
    console.log('  No profile record found.');
  } else {
    for (const rec of profiles) {
      await deleteRecord(agent, community.did, 'community.opensocial.profile', rec.rkey, dryRun);
    }
  }

  // 4. Optionally delete the community row from the local DB
  if (deleteDbRow) {
    console.log('\n── Local database ──');
    if (dryRun) {
      console.log('  [DRY RUN] Would delete community row from the database.');
    } else {
      await db
        .deleteFrom('communities')
        .where('did', '=', community.did)
        .execute();
      console.log('  ✅ Deleted community row from the database.');
    }
  }
}

// ── User cleanup ─────────────────────────────────────────────────────────────

async function clearUserData(
  did: string,
  pdsHost: string,
  appPassword: string,
  dryRun: boolean
) {
  console.log(`Treating ${did} as a user account.`);
  console.log(`PDS host: ${pdsHost}\n`);

  // Authenticate as the user
  const agent = new BskyAgent({ service: pdsServiceUrl(pdsHost) });
  await agent.login({
    identifier: did,
    password: appPassword,
  });
  console.log('🔑 Authenticated as user account.\n');

  // Delete all community.opensocial.membership records
  console.log('── community.opensocial.membership ──');
  const memberships = await listRecords(agent, did, 'community.opensocial.membership');
  if (memberships.length === 0) {
    console.log('  No membership records found.');
  } else {
    console.log(`  Found ${memberships.length} membership record(s).`);
    for (const rec of memberships) {
      await deleteRecord(agent, did, 'community.opensocial.membership', rec.rkey, dryRun);
    }
  }
}

// ── Run ──────────────────────────────────────────────────────────────────────

main().catch((err) => {
  console.error('\n❌ Fatal error:', err);
  process.exit(1);
});
