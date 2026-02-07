#!/usr/bin/env tsx
"use strict";
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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var dotenv_1 = require("dotenv");
var api_1 = require("@atproto/api");
var kysely_1 = require("kysely");
var pg_1 = require("pg");
var crypto_1 = require("../src/lib/crypto");
dotenv_1.default.config();
// ── Helpers ──────────────────────────────────────────────────────────────────
function pdsServiceUrl(pdsHost) {
    if (pdsHost.startsWith('http://') || pdsHost.startsWith('https://')) {
        return pdsHost;
    }
    return "https://".concat(pdsHost);
}
/**
 * Resolve a DID to its PDS endpoint via plc.directory (for did:plc:)
 * or by fetching the DID document directly (for did:web:).
 */
function resolvePdsFromDid(did) {
    return __awaiter(this, void 0, void 0, function () {
        var didDoc, res, host, res, services, pdsSvc;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (!did.startsWith('did:plc:')) return [3 /*break*/, 3];
                    return [4 /*yield*/, fetch("https://plc.directory/".concat(did))];
                case 1:
                    res = _a.sent();
                    if (!res.ok) {
                        throw new Error("Failed to resolve ".concat(did, " via plc.directory (HTTP ").concat(res.status, ")"));
                    }
                    return [4 /*yield*/, res.json()];
                case 2:
                    didDoc = _a.sent();
                    return [3 /*break*/, 7];
                case 3:
                    if (!did.startsWith('did:web:')) return [3 /*break*/, 6];
                    host = did.replace('did:web:', '');
                    return [4 /*yield*/, fetch("https://".concat(host, "/.well-known/did.json"))];
                case 4:
                    res = _a.sent();
                    if (!res.ok) {
                        throw new Error("Failed to resolve ".concat(did, " via did:web (HTTP ").concat(res.status, ")"));
                    }
                    return [4 /*yield*/, res.json()];
                case 5:
                    didDoc = _a.sent();
                    return [3 /*break*/, 7];
                case 6: throw new Error("Unsupported DID method: ".concat(did));
                case 7:
                    services = didDoc.service || [];
                    pdsSvc = services.find(function (s) { return s.id === '#atproto_pds' || s.type === 'AtprotoPersonalDataServer'; });
                    if (!(pdsSvc === null || pdsSvc === void 0 ? void 0 : pdsSvc.serviceEndpoint)) {
                        throw new Error("No PDS service endpoint found in DID document for ".concat(did));
                    }
                    return [2 /*return*/, pdsSvc.serviceEndpoint];
            }
        });
    });
}
function usage() {
    console.log("\nUsage:\n  npx tsx scripts/clearData.ts <did> [options]\n\nOptions:\n  --delete-db-row              Also delete the community row from the local DB\n  --user-pds <host>            PDS host override (auto-resolved from DID if omitted)\n  --user-password <password>   App password for the user DID\n  --dry-run                    Show what would be deleted without actually deleting\n  --help                       Show this help message\n");
    process.exit(1);
}
function parseArgs(argv) {
    var args = argv.slice(2);
    if (args.length === 0 || args.includes('--help'))
        usage();
    var deleteDbRow = args.includes('--delete-db-row');
    var dryRun = args.includes('--dry-run');
    var userPds;
    var userPassword;
    var pdsIdx = args.indexOf('--user-pds');
    if (pdsIdx !== -1)
        userPds = args[pdsIdx + 1];
    var pwIdx = args.indexOf('--user-password');
    if (pwIdx !== -1)
        userPassword = args[pwIdx + 1];
    // Flags that consume a value after them
    var flagsWithValue = new Set(['--user-pds', '--user-password']);
    var bareFlags = new Set(['--delete-db-row', '--dry-run', '--help']);
    // Find the positional DID argument (first arg that isn't a flag or a flag's value)
    var did;
    for (var i = 0; i < args.length; i++) {
        if (flagsWithValue.has(args[i])) {
            i++; // skip the flag's value
            continue;
        }
        if (bareFlags.has(args[i]))
            continue;
        did = args[i];
        break;
    }
    if (!did) {
        console.error('❌ No DID provided.\n');
        usage();
    }
    return { did: did, deleteDbRow: deleteDbRow, dryRun: dryRun, userPds: userPds, userPassword: userPassword };
}
function listRecords(agent, repo, collection) {
    return __awaiter(this, void 0, void 0, function () {
        var records, cursor, res, _i, _a, rec, rkey;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    records = [];
                    _b.label = 1;
                case 1: return [4 /*yield*/, agent.com.atproto.repo.listRecords({
                        repo: repo,
                        collection: collection,
                        limit: 100,
                        cursor: cursor,
                    })];
                case 2:
                    res = _b.sent();
                    for (_i = 0, _a = res.data.records; _i < _a.length; _i++) {
                        rec = _a[_i];
                        rkey = rec.uri.split('/').pop();
                        records.push({ uri: rec.uri, rkey: rkey });
                    }
                    cursor = res.data.cursor;
                    _b.label = 3;
                case 3:
                    if (cursor) return [3 /*break*/, 1];
                    _b.label = 4;
                case 4: return [2 /*return*/, records];
            }
        });
    });
}
function deleteRecord(agent, repo, collection, rkey, dryRun) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (dryRun) {
                        console.log("  [DRY RUN] Would delete ".concat(collection, "/").concat(rkey));
                        return [2 /*return*/];
                    }
                    return [4 /*yield*/, agent.com.atproto.repo.deleteRecord({ repo: repo, collection: collection, rkey: rkey })];
                case 1:
                    _a.sent();
                    console.log("  \u2705 Deleted ".concat(collection, "/").concat(rkey));
                    return [2 /*return*/];
            }
        });
    });
}
// ── Main ─────────────────────────────────────────────────────────────────────
function main() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, did, deleteDbRow, dryRun, userPds, userPassword, db, community, resolvedPds;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _a = parseArgs(process.argv), did = _a.did, deleteDbRow = _a.deleteDbRow, dryRun = _a.dryRun, userPds = _a.userPds, userPassword = _a.userPassword;
                    if (!process.env.DATABASE_URL) {
                        console.error('❌ DATABASE_URL is not set. Add it to .env or pass it as an env var.');
                        process.exit(1);
                    }
                    db = new kysely_1.Kysely({
                        dialect: new kysely_1.PostgresDialect({
                            pool: new pg_1.Pool({ connectionString: process.env.DATABASE_URL }),
                        }),
                    });
                    if (dryRun) {
                        console.log('🔍 DRY RUN — no records will actually be deleted.\n');
                    }
                    console.log("Looking up DID: ".concat(did, "\n"));
                    return [4 /*yield*/, db
                            .selectFrom('communities')
                            .select(['did', 'handle', 'pds_host', 'app_password'])
                            .where('did', '=', did)
                            .executeTakeFirst()];
                case 1:
                    community = _b.sent();
                    if (!community) return [3 /*break*/, 3];
                    return [4 /*yield*/, clearCommunityData(db, community, deleteDbRow, dryRun)];
                case 2:
                    _b.sent();
                    return [3 /*break*/, 8];
                case 3:
                    if (!userPassword) return [3 /*break*/, 7];
                    resolvedPds = userPds;
                    if (!!resolvedPds) return [3 /*break*/, 5];
                    console.log('Resolving PDS host from DID document...');
                    return [4 /*yield*/, resolvePdsFromDid(did)];
                case 4:
                    resolvedPds = _b.sent();
                    console.log("Resolved PDS: ".concat(resolvedPds, "\n"));
                    _b.label = 5;
                case 5: return [4 /*yield*/, clearUserData(did, resolvedPds, userPassword, dryRun)];
                case 6:
                    _b.sent();
                    return [3 /*break*/, 8];
                case 7:
                    console.log("DID ".concat(did, " is not a community in the database."));
                    console.log("To clear a user's data, provide --user-password (PDS is auto-resolved).\n");
                    console.log('Example:');
                    console.log("  npx tsx scripts/clearData.ts ".concat(did, " --user-password app-pass-xxxx-xxxx"));
                    process.exit(1);
                    _b.label = 8;
                case 8: return [4 /*yield*/, db.destroy()];
                case 9:
                    _b.sent();
                    console.log('\n🏁 Done.');
                    return [2 /*return*/];
            }
        });
    });
}
// ── Community cleanup ────────────────────────────────────────────────────────
function clearCommunityData(db, community, deleteDbRow, dryRun) {
    return __awaiter(this, void 0, void 0, function () {
        var agent, members, _i, members_1, rec, admins, _a, admins_1, rec, profiles, _b, profiles_1, rec;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    console.log("Found community: ".concat(community.handle, " (").concat(community.did, ")"));
                    console.log("PDS host: ".concat(community.pds_host, "\n"));
                    agent = new api_1.BskyAgent({ service: pdsServiceUrl(community.pds_host) });
                    return [4 /*yield*/, agent.login({
                            identifier: community.handle,
                            password: (0, crypto_1.decryptIfNeeded)(community.app_password),
                        })];
                case 1:
                    _c.sent();
                    console.log('🔑 Authenticated as community account.\n');
                    // 1. Delete all community.opensocial.member records (tid-keyed)
                    console.log('── community.opensocial.member ──');
                    return [4 /*yield*/, listRecords(agent, community.did, 'community.opensocial.member')];
                case 2:
                    members = _c.sent();
                    if (!(members.length === 0)) return [3 /*break*/, 3];
                    console.log('  No member records found.');
                    return [3 /*break*/, 7];
                case 3:
                    console.log("  Found ".concat(members.length, " member record(s)."));
                    _i = 0, members_1 = members;
                    _c.label = 4;
                case 4:
                    if (!(_i < members_1.length)) return [3 /*break*/, 7];
                    rec = members_1[_i];
                    return [4 /*yield*/, deleteRecord(agent, community.did, 'community.opensocial.member', rec.rkey, dryRun)];
                case 5:
                    _c.sent();
                    _c.label = 6;
                case 6:
                    _i++;
                    return [3 /*break*/, 4];
                case 7:
                    // 2. Delete the community.opensocial.admins record
                    console.log('\n── community.opensocial.admins ──');
                    return [4 /*yield*/, listRecords(agent, community.did, 'community.opensocial.admins')];
                case 8:
                    admins = _c.sent();
                    if (!(admins.length === 0)) return [3 /*break*/, 9];
                    console.log('  No admins record found.');
                    return [3 /*break*/, 13];
                case 9:
                    _a = 0, admins_1 = admins;
                    _c.label = 10;
                case 10:
                    if (!(_a < admins_1.length)) return [3 /*break*/, 13];
                    rec = admins_1[_a];
                    return [4 /*yield*/, deleteRecord(agent, community.did, 'community.opensocial.admins', rec.rkey, dryRun)];
                case 11:
                    _c.sent();
                    _c.label = 12;
                case 12:
                    _a++;
                    return [3 /*break*/, 10];
                case 13:
                    // 3. Delete the community.opensocial.profile record
                    console.log('\n── community.opensocial.profile ──');
                    return [4 /*yield*/, listRecords(agent, community.did, 'community.opensocial.profile')];
                case 14:
                    profiles = _c.sent();
                    if (!(profiles.length === 0)) return [3 /*break*/, 15];
                    console.log('  No profile record found.');
                    return [3 /*break*/, 19];
                case 15:
                    _b = 0, profiles_1 = profiles;
                    _c.label = 16;
                case 16:
                    if (!(_b < profiles_1.length)) return [3 /*break*/, 19];
                    rec = profiles_1[_b];
                    return [4 /*yield*/, deleteRecord(agent, community.did, 'community.opensocial.profile', rec.rkey, dryRun)];
                case 17:
                    _c.sent();
                    _c.label = 18;
                case 18:
                    _b++;
                    return [3 /*break*/, 16];
                case 19:
                    if (!deleteDbRow) return [3 /*break*/, 22];
                    console.log('\n── Local database ──');
                    if (!dryRun) return [3 /*break*/, 20];
                    console.log('  [DRY RUN] Would delete community row from the database.');
                    return [3 /*break*/, 22];
                case 20: return [4 /*yield*/, db
                        .deleteFrom('communities')
                        .where('did', '=', community.did)
                        .execute()];
                case 21:
                    _c.sent();
                    console.log('  ✅ Deleted community row from the database.');
                    _c.label = 22;
                case 22: return [2 /*return*/];
            }
        });
    });
}
// ── User cleanup ─────────────────────────────────────────────────────────────
function clearUserData(did, pdsHost, appPassword, dryRun) {
    return __awaiter(this, void 0, void 0, function () {
        var agent, memberships, _i, memberships_1, rec;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.log("Treating ".concat(did, " as a user account."));
                    console.log("PDS host: ".concat(pdsHost, "\n"));
                    agent = new api_1.BskyAgent({ service: pdsServiceUrl(pdsHost) });
                    return [4 /*yield*/, agent.login({
                            identifier: did,
                            password: appPassword,
                        })];
                case 1:
                    _a.sent();
                    console.log('🔑 Authenticated as user account.\n');
                    // Delete all community.opensocial.membership records
                    console.log('── community.opensocial.membership ──');
                    return [4 /*yield*/, listRecords(agent, did, 'community.opensocial.membership')];
                case 2:
                    memberships = _a.sent();
                    if (!(memberships.length === 0)) return [3 /*break*/, 3];
                    console.log('  No membership records found.');
                    return [3 /*break*/, 7];
                case 3:
                    console.log("  Found ".concat(memberships.length, " membership record(s)."));
                    _i = 0, memberships_1 = memberships;
                    _a.label = 4;
                case 4:
                    if (!(_i < memberships_1.length)) return [3 /*break*/, 7];
                    rec = memberships_1[_i];
                    return [4 /*yield*/, deleteRecord(agent, did, 'community.opensocial.membership', rec.rkey, dryRun)];
                case 5:
                    _a.sent();
                    _a.label = 6;
                case 6:
                    _i++;
                    return [3 /*break*/, 4];
                case 7: return [2 /*return*/];
            }
        });
    });
}
// ── Run ──────────────────────────────────────────────────────────────────────
main().catch(function (err) {
    console.error('\n❌ Fatal error:', err);
    process.exit(1);
});
