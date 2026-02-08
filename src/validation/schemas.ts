import { z } from 'zod';

// Common schemas
export const didSchema = z.string().min(1, 'DID is required').startsWith('did:');
export const handleSchema = z.string().min(1, 'Handle is required');
export const cursorSchema = z.string().optional();
export const limitSchema = z.coerce.number().int().min(1).max(100).default(20);

// App schemas
export const registerAppSchema = z.object({
  name: z.string().min(3).max(100).regex(/^[a-zA-Z0-9\s\-_]+$/, 'Name must be alphanumeric with spaces, hyphens, or underscores'),
  domain: z.string().min(1).regex(/^[a-zA-Z0-9][a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}$/, 'Invalid domain format'),
});

export const updateAppSchema = z.object({
  name: z.string().min(3).max(100).regex(/^[a-zA-Z0-9\s\-_]+$/).optional(),
  domain: z.string().min(1).regex(/^[a-zA-Z0-9][a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}$/).optional(),
}).refine(data => data.name || data.domain, { message: 'At least one field (name or domain) is required' });

// Community schemas
export const createCommunityApiKeySchema = z.object({
  did: didSchema,
  appPassword: z.string().min(1, 'App password is required'),
  displayName: z.string().min(1).max(64),
  creatorDid: didSchema,
  description: z.string().max(512).optional(),
});

export const createCommunityOAuthSchema = z.object({
  did: didSchema,
  appPassword: z.string().min(1, 'App password is required'),
  displayName: z.string().min(1).max(64),
  description: z.string().max(512).optional(),
});

export const updateCommunityProfileSchema = z.object({
  displayName: z.string().min(1).max(64),
  description: z.string().max(512).optional(),
  type: z.enum(['open', 'admin-approved', 'private']).optional(),
  guidelines: z.string().max(3000).optional(),
});

export const searchCommunitiesSchema = z.object({
  query: z.string().optional(),
  userDid: didSchema.optional(),
  cursor: cursorSchema,
  limit: limitSchema,
});

// Member schemas
export const joinCommunitySchema = z.object({
  userDid: didSchema,
  membershipCid: z.string().optional(),
});

export const approveMemberSchema = z.object({
  adminDid: didSchema,
  memberDid: didSchema,
  reason: z.string().max(500).optional(),
});

export const rejectMemberSchema = z.object({
  adminDid: didSchema,
  memberDid: didSchema,
  reason: z.string().max(500).optional(),
});

export const removeMemberSchema = z.object({
  adminDid: didSchema,
  memberDid: didSchema,
  reason: z.string().max(500).optional(),
});

export const leaveCommunitySchema = z.object({
  userDid: didSchema,
});

export const listMembersSchema = z.object({
  adminDid: didSchema.optional(),
  public: z.string().optional(),
  search: z.string().optional(),
  cursor: cursorSchema,
  limit: limitSchema,
});

export const promoteMemberSchema = z.object({
  adminDid: didSchema,
  memberDid: didSchema,
});

export const demoteMemberSchema = z.object({
  adminDid: didSchema,
  memberDid: didSchema,
});

export const transferAdminSchema = z.object({
  currentOwnerDid: didSchema,
  newOwnerDid: didSchema,
});

export const deleteCommunitySchema = z.object({
  adminDid: didSchema,
});

// Record schemas
export const createRecordSchema = z.object({
  collection: z.string().min(1, 'Collection is required'),
  record: z.record(z.string(), z.any()).refine(r => r['$type'], { message: 'Record must include $type' }),
  userDid: didSchema,
  rkey: z.string().optional(),
});

export const updateRecordSchema = z.object({
  collection: z.string().min(1),
  rkey: z.string().min(1, 'Record key is required'),
  record: z.record(z.string(), z.any()).refine(r => r['$type'], { message: 'Record must include $type' }),
  userDid: didSchema,
});

export const deleteRecordSchema = z.object({
  userDid: didSchema,
});

export const listRecordsSchema = z.object({
  limit: limitSchema,
  cursor: cursorSchema,
});

export const membershipCheckSchema = z.object({
  userDid: didSchema,
});

// Webhook schemas
export const createWebhookSchema = z.object({
  url: z.string().url('Must be a valid URL'),
  events: z.array(z.enum([
    'member.joined',
    'member.left',
    'member.approved',
    'member.rejected',
    'member.removed',
    'record.created',
    'record.updated',
    'record.deleted',
  ])).min(1, 'At least one event is required'),
  communityDid: didSchema.optional(),
});

export const updateWebhookSchema = z.object({
  url: z.string().url().optional(),
  events: z.array(z.enum([
    'member.joined',
    'member.left',
    'member.approved',
    'member.rejected',
    'member.removed',
    'record.created',
    'record.updated',
    'record.deleted',
  ])).min(1).optional(),
  active: z.boolean().optional(),
});

// Login schema
export const loginSchema = z.object({
  handle: z.string().min(1, 'Handle is required'),
});

// Audit log query
export const auditLogQuerySchema = z.object({
  adminDid: didSchema,
  cursor: cursorSchema,
  limit: limitSchema,
});
