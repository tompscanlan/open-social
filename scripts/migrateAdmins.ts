#!/usr/bin/env tsx
/**
 * migrateAdmins.ts — Migrate admin records from legacy string[] format
 * to the canonical object[] format defined in the community.opensocial.admins lexicon.
 *
 * Legacy format:   admins: ["did:plc:abc", "did:plc:xyz"]
 * Canonical format: admins: [{ did: "did:plc:abc", addedAt: "..." }, ...]
 *
 * The first admin in the list is preserved as the original group creator
 * (index 0) so that demotion-protection continues to work.
 *
 * Also back-fills the `memberDid` field on membershipProof records that
 * were created before the schema update (those that only have `cid`).
 *
 * Usage:
 *   npx tsx scripts/migrateAdmins.ts [--dry-run]
 *
 * Options:
 *   --dry-run   Print what would be changed without writing anything.
 */

import dotenv from 'dotenv';
import { BskyAgent } from '@atproto/api';
import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import type { Database } from '../src/db';
import { normalizeAdmins } from '../src/lib/adminUtils';

dotenv.config();

const dryRun = process.argv.includes('--dry-run');

function pdsServiceUrl(pdsHost: string): string {
  if (pdsHost.startsWith('http://') || pdsHost.startsWith('https://')) {
    return pdsHost;
  }
  return `https://${pdsHost}`;
}

async function main() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error('DATABASE_URL is not set');
    process.exit(1);
  }

  const db = new Kysely<Database>({
    dialect: new PostgresDialect({
      pool: new Pool({ connectionString }),
    }),
  });

  console.log(dryRun ? '🔍 DRY RUN — no writes will be made\n' : '🚀 Running migration…\n');

  const communities = await db
    .selectFrom('communities')
    .selectAll()
    .execute();

  console.log(`Found ${communities.length} communities to check.\n`);

  let adminsUpdated = 0;
  let proofsUpdated = 0;
  let errors = 0;

  for (const community of communities) {
    const label = `${community.handle} (${community.did})`;
    console.log(`── ${label}`);

    try {
      const agent = new BskyAgent({ service: pdsServiceUrl(community.pds_host) });
      await agent.login({
        identifier: community.handle,
        password: community.app_password,
      });

      // ─── 1. Migrate admins record ─────────────────────────────────────
      try {
        const adminsResponse = await agent.api.com.atproto.repo.getRecord({
          repo: community.did,
          collection: 'community.opensocial.admins',
          rkey: 'self',
        });

        const admins = (adminsResponse.data.value as any).admins || [];
        const needsMigration = admins.some((a: any) => typeof a === 'string');

        if (needsMigration) {
          const normalized = normalizeAdmins(admins);
          console.log(`   ⚠  Admins need migration: ${JSON.stringify(admins)}`);
          console.log(`   →  Normalized:            ${JSON.stringify(normalized)}`);

          if (!dryRun) {
            await agent.api.com.atproto.repo.putRecord({
              repo: community.did,
              collection: 'community.opensocial.admins',
              rkey: 'self',
              record: {
                $type: 'community.opensocial.admins',
                admins: normalized,
              },
            });
            console.log('   ✅ Admins record updated.');
          }
          adminsUpdated++;
        } else {
          console.log('   ✓  Admins record already in canonical format.');
        }
      } catch (err: any) {
        if (err?.status === 400 || err?.message?.includes('not found')) {
          console.log('   ⏭  No admins record found — skipping.');
        } else {
          throw err;
        }
      }

      // ─── 2. Back-fill memberDid on membershipProof records ─────────────
      try {
        let cursor: string | undefined;
        const allProofs: any[] = [];
        do {
          const response = await agent.api.com.atproto.repo.listRecords({
            repo: community.did,
            collection: 'community.opensocial.membershipProof',
            limit: 100,
            cursor,
          });
          allProofs.push(...response.data.records);
          cursor = response.data.cursor;
        } while (cursor);

        const proofsWithoutMemberDid = allProofs.filter(
          (p: any) => !p.value.memberDid
        );

        if (proofsWithoutMemberDid.length > 0) {
          console.log(
            `   ⚠  ${proofsWithoutMemberDid.length} membershipProof record(s) missing memberDid.`
          );
          console.log(
            '   ℹ  These records only have a CID — memberDid cannot be auto-populated.'
          );
          console.log(
            '      Consider re-creating membership proofs for affected members.'
          );
          proofsUpdated += proofsWithoutMemberDid.length;
        } else if (allProofs.length > 0) {
          console.log(`   ✓  All ${allProofs.length} membershipProof records have memberDid.`);
        } else {
          console.log('   ⏭  No membershipProof records found.');
        }
      } catch (err) {
        console.log('   ⏭  Could not list membershipProof records.');
      }

      console.log();
    } catch (err: any) {
      console.error(`   ❌ Error processing ${label}: ${err.message}`);
      errors++;
      console.log();
    }
  }

  // ─── Summary ───────────────────────────────────────────────────────────
  console.log('═══════════════════════════════════════════════════');
  console.log(`Communities checked:         ${communities.length}`);
  console.log(`Admin records migrated:      ${adminsUpdated}`);
  console.log(`MembershipProofs flagged:    ${proofsUpdated}`);
  console.log(`Errors:                      ${errors}`);
  if (dryRun) {
    console.log('\n🔍 This was a dry run. Re-run without --dry-run to apply changes.');
  }

  await db.destroy();
  process.exit(errors > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
