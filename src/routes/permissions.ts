/**
 * Routes for managing community-level permissions, app visibility,
 * collection-level permission overrides, custom roles, and role assignments.
 *
 * All routes are mounted under /api/v1/communities and protected by API key auth.
 * Admin-only operations verify the caller via the AT Proto admins record.
 */

import { Router } from 'express';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { createVerifyApiKey, type AuthenticatedRequest } from '../middleware/auth';
import {
  updateCommunitySettingsSchema,
  updateAppVisibilitySchema,
  setCollectionPermissionSchema,
  deleteCollectionPermissionSchema,
  createRoleSchema,
  updateRoleSchema,
  deleteRoleSchema,
  assignRoleSchema,
  revokeRoleSchema,
} from '../validation/schemas';
import { createCommunityAgent } from '../services/atproto';
import { checkAdmin, seedCollectionPermissions } from '../services/permissions';
import { createAuditLogService } from '../services/auditLog';
import { adminCache, memberCache, memberRolesCache } from '../lib/cache';
import { logger } from '../lib/logger';

export function createPermissionsRouter(db: Kysely<Database>): Router {
  const router = Router();
  const verifyApiKey = createVerifyApiKey(db);
  const auditLog = createAuditLogService(db);

  // ─── Helper: verify caller is admin ─────────────────────────────────

  async function requireAdmin(communityDid: string, adminDid: string, res: any): Promise<any | null> {
    const communityAgent = await createCommunityAgent(db, communityDid);
    const isAdm = await checkAdmin(communityAgent, communityDid, adminDid);
    if (!isAdm) {
      res.status(403).json({ error: 'Not authorized. Must be an admin.' });
      return null;
    }
    return communityAgent;
  }

  // ═══════════════════════════════════════════════════════════════════
  // COMMUNITY SETTINGS
  // ═══════════════════════════════════════════════════════════════════

  /**
   * GET /:did/settings
   * Retrieve the community's permission settings.
   */
  router.get('/:did/settings', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    try {

      const settings = await db
        .selectFrom('community_settings')
        .selectAll()
        .where('community_did', '=', communityDid)
        .executeTakeFirst();

      if (!settings) {
        // Return defaults
        return res.json({
          settings: {
            communityDid,
            appVisibilityDefault: 'open',
            blockedAppIds: [],
          },
        });
      }

      res.json({
        settings: {
          communityDid: settings.community_did,
          appVisibilityDefault: settings.app_visibility_default,
          blockedAppIds: JSON.parse(settings.blocked_app_ids),
        },
      });
    } catch (error) {
      logger.error({ error, communityDid }, 'Error getting community settings');
      res.status(500).json({ error: 'Failed to get community settings' });
    }
  });

  /**
   * PUT /:did/settings
   * Update community-level permission settings (admin only).
   */
  router.put('/:did/settings', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    try {
      const parsed = updateCommunitySettingsSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid, appVisibilityDefault, blockedAppIds } = parsed.data;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      const existing = await db
        .selectFrom('community_settings')
        .selectAll()
        .where('community_did', '=', communityDid)
        .executeTakeFirst();

      const values: Record<string, any> = { updated_at: new Date() };
      if (appVisibilityDefault) values.app_visibility_default = appVisibilityDefault;
      if (blockedAppIds) values.blocked_app_ids = JSON.stringify(blockedAppIds);

      if (existing) {
        await db
          .updateTable('community_settings')
          .set(values)
          .where('community_did', '=', communityDid)
          .execute();
      } else {
        await db
          .insertInto('community_settings')
          .values({
            community_did: communityDid,
            app_visibility_default: appVisibilityDefault || 'open',
            blocked_app_ids: blockedAppIds ? JSON.stringify(blockedAppIds) : '[]',
          })
          .execute();
      }

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'settings.updated',
        metadata: { appVisibilityDefault, blockedAppIds },
      });

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid }, 'Error updating community settings');
      res.status(500).json({ error: 'Failed to update community settings' });
    }
  });

  // ═══════════════════════════════════════════════════════════════════
  // APP VISIBILITY
  // ═══════════════════════════════════════════════════════════════════

  /**
   * GET /:did/apps
   * List all app visibility overrides for this community.
   */
  router.get('/:did/apps', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    try {

      const rows = await db
        .selectFrom('community_app_visibility')
        .selectAll()
        .where('community_did', '=', communityDid)
        .orderBy('created_at', 'desc')
        .execute();

      // Enrich with app name
      const enriched = await Promise.all(
        rows.map(async (row) => {
          const app = await db
            .selectFrom('apps')
            .select(['name', 'domain'])
            .where('app_id', '=', row.app_id)
            .executeTakeFirst();
          return {
            appId: row.app_id,
            appName: app?.name || null,
            appDomain: app?.domain || null,
            status: row.status,
            reviewedBy: row.reviewed_by,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
          };
        }),
      );

      res.json({ apps: enriched });
    } catch (error) {
      logger.error({ error, communityDid }, 'Error listing app visibility');
      res.status(500).json({ error: 'Failed to list app visibility' });
    }
  });

  /**
   * PUT /:did/apps/:appId
   * Enable, disable, or set pending status for an app on this community (admin only).
   * When enabling, seeds default collection permissions from the app's defaults.
   */
  router.put('/:did/apps/:appId', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const appId = req.params.appId;
    try {
      const parsed = updateAppVisibilitySchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid, status } = parsed.data;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      // Verify the app exists
      const app = await db
        .selectFrom('apps')
        .select('app_id')
        .where('app_id', '=', appId)
        .executeTakeFirst();
      if (!app) {
        return res.status(404).json({ error: 'App not found' });
      }

      // Upsert visibility
      const existing = await db
        .selectFrom('community_app_visibility')
        .selectAll()
        .where('community_did', '=', communityDid)
        .where('app_id', '=', appId)
        .executeTakeFirst();

      if (existing) {
        await db
          .updateTable('community_app_visibility')
          .set({ status, reviewed_by: adminDid, updated_at: new Date() })
          .where('id', '=', existing.id)
          .execute();
      } else {
        await db
          .insertInto('community_app_visibility')
          .values({
            community_did: communityDid,
            app_id: appId,
            status,
            requested_by: adminDid,
            reviewed_by: adminDid,
          })
          .execute();
      }

      // When enabling, seed default collection permissions
      if (status === 'enabled') {
        await seedCollectionPermissions(db, communityDid, appId);
      }

      await auditLog.log({
        communityDid,
        adminDid,
        action: `app.visibility.${status}`,
        metadata: { appId },
      });

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid, appId }, 'Error updating app visibility');
      res.status(500).json({ error: 'Failed to update app visibility' });
    }
  });

  // ═══════════════════════════════════════════════════════════════════
  // COLLECTION PERMISSIONS
  // ═══════════════════════════════════════════════════════════════════

  /**
   * GET /:did/apps/:appId/permissions
   * List collection-level permissions for an app on this community.
   */
  router.get('/:did/apps/:appId/permissions', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const appId = req.params.appId;
    try {

      const rows = await db
        .selectFrom('community_app_collection_permissions')
        .selectAll()
        .where('community_did', '=', communityDid)
        .where('app_id', '=', appId)
        .orderBy('collection', 'asc')
        .execute();

      res.json({
        permissions: rows.map((r) => ({
          collection: r.collection,
          canCreate: r.can_create,
          canRead: r.can_read,
          canUpdate: r.can_update,
          canDelete: r.can_delete,
        })),
      });
    } catch (error) {
      logger.error({ error, communityDid, appId }, 'Error listing collection permissions');
      res.status(500).json({ error: 'Failed to list collection permissions' });
    }
  });

  /**
   * PUT /:did/apps/:appId/permissions
   * Set or update a collection permission for an app on this community (admin only).
   */
  router.put('/:did/apps/:appId/permissions', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const appId = req.params.appId;
    let collection: string | undefined;
    try {
      const parsed = setCollectionPermissionSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid, canCreate, canRead, canUpdate, canDelete } = parsed.data;
      collection = parsed.data.collection;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      const existing = await db
        .selectFrom('community_app_collection_permissions')
        .selectAll()
        .where('community_did', '=', communityDid)
        .where('app_id', '=', appId)
        .where('collection', '=', collection)
        .executeTakeFirst();

      if (existing) {
        const updates: Record<string, any> = { updated_at: new Date() };
        if (canCreate) updates.can_create = canCreate;
        if (canRead) updates.can_read = canRead;
        if (canUpdate) updates.can_update = canUpdate;
        if (canDelete) updates.can_delete = canDelete;
        await db
          .updateTable('community_app_collection_permissions')
          .set(updates)
          .where('id', '=', existing.id)
          .execute();
      } else {
        await db
          .insertInto('community_app_collection_permissions')
          .values({
            community_did: communityDid,
            app_id: appId,
            collection,
            can_create: canCreate || 'member',
            can_read: canRead || 'member',
            can_update: canUpdate || 'member',
            can_delete: canDelete || 'admin',
          })
          .execute();
      }

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'collection.permission.updated',
        metadata: { appId, collection, canCreate, canRead, canUpdate, canDelete },
      });

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid, appId, collection }, 'Error setting collection permission');
      res.status(500).json({ error: 'Failed to set collection permission' });
    }
  });

  /**
   * DELETE /:did/apps/:appId/permissions
   * Remove a collection permission entry (revokes access for that collection via this app).
   */
  router.delete('/:did/apps/:appId/permissions', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const appId = req.params.appId;
    try {
      const parsed = deleteCollectionPermissionSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid, collection } = parsed.data;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      await db
        .deleteFrom('community_app_collection_permissions')
        .where('community_did', '=', communityDid)
        .where('app_id', '=', appId)
        .where('collection', '=', collection)
        .execute();

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'collection.permission.deleted',
        metadata: { appId, collection },
      });

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid, appId }, 'Error deleting collection permission');
      res.status(500).json({ error: 'Failed to delete collection permission' });
    }
  });

  // ═══════════════════════════════════════════════════════════════════
  // CUSTOM ROLES
  // ═══════════════════════════════════════════════════════════════════

  /**
   * GET /:did/roles
   * List all custom roles for a community.
   */
  router.get('/:did/roles', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    try {

      const roles = await db
        .selectFrom('community_roles')
        .selectAll()
        .where('community_did', '=', communityDid)
        .orderBy('name', 'asc')
        .execute();

      res.json({
        roles: roles.map((r) => ({
          name: r.name,
          displayName: r.display_name,
          description: r.description,
          visible: r.visible,
          canViewAuditLog: r.can_view_audit_log,
          createdAt: r.created_at,
        })),
      });
    } catch (error) {
      logger.error({ error, communityDid }, 'Error listing roles');
      res.status(500).json({ error: 'Failed to list roles' });
    }
  });

  /**
   * POST /:did/roles
   * Create a custom role (admin only).
   */
  router.post('/:did/roles', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    let name: string | undefined;
    try {
      const parsed = createRoleSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid, displayName, description, visible } = parsed.data;
      name = parsed.data.name;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      // Prevent using built-in role names
      if (name === 'admin' || name === 'member') {
        return res.status(400).json({ error: `"${name}" is a built-in role and cannot be created` });
      }

      // Check for duplicate
      const existing = await db
        .selectFrom('community_roles')
        .select('id')
        .where('community_did', '=', communityDid)
        .where('name', '=', name)
        .executeTakeFirst();
      if (existing) {
        return res.status(409).json({ error: `Role "${name}" already exists in this community` });
      }

      await db
        .insertInto('community_roles')
        .values({
          community_did: communityDid,
          name,
          display_name: displayName,
          description: description || null,
          visible,
          can_view_audit_log: (parsed.data as any).canViewAuditLog ?? false,
        })
        .execute();

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'role.created',
        metadata: { name, displayName, visible },
      });

      res.status(201).json({ success: true, role: { name, displayName, description, visible } });
    } catch (error) {
      logger.error({ error, communityDid, name }, 'Error creating role');
      res.status(500).json({ error: 'Failed to create role' });
    }
  });

  /**
   * PUT /:did/roles/:roleName
   * Update a custom role (admin only).
   */
  router.put('/:did/roles/:roleName', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const roleName = req.params.roleName;
    try {
      const parsed = updateRoleSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid, displayName, description, visible } = parsed.data;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      const existing = await db
        .selectFrom('community_roles')
        .select('id')
        .where('community_did', '=', communityDid)
        .where('name', '=', roleName)
        .executeTakeFirst();
      if (!existing) {
        return res.status(404).json({ error: 'Role not found' });
      }

      const updates: Record<string, any> = { updated_at: new Date() };
      if (displayName !== undefined) updates.display_name = displayName;
      if (description !== undefined) updates.description = description;
      if (visible !== undefined) updates.visible = visible;
      if ((req.body as any).canViewAuditLog !== undefined) updates.can_view_audit_log = (req.body as any).canViewAuditLog;

      await db
        .updateTable('community_roles')
        .set(updates)
        .where('community_did', '=', communityDid)
        .where('name', '=', roleName)
        .execute();

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'role.updated',
        metadata: { roleName, displayName, description, visible },
      });

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid, roleName }, 'Error updating role');
      res.status(500).json({ error: 'Failed to update role' });
    }
  });

  /**
   * DELETE /:did/roles/:roleName
   * Delete a custom role (admin only).
   * Also removes all member-role assignments for this role.
   */
  router.delete('/:did/roles/:roleName', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const roleName = req.params.roleName;
    try {
      const parsed = deleteRoleSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid } = parsed.data;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      // Delete all assignments first
      await db
        .deleteFrom('community_member_roles')
        .where('community_did', '=', communityDid)
        .where('role_name', '=', roleName)
        .execute();

      const result = await db
        .deleteFrom('community_roles')
        .where('community_did', '=', communityDid)
        .where('name', '=', roleName)
        .executeTakeFirst();

      if (!result.numDeletedRows || result.numDeletedRows === 0n) {
        return res.status(404).json({ error: 'Role not found' });
      }

      // Invalidate caches for this community
      memberRolesCache.invalidatePrefix(`${communityDid}:`);

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'role.deleted',
        metadata: { roleName },
      });

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid, roleName }, 'Error deleting role');
      res.status(500).json({ error: 'Failed to delete role' });
    }
  });

  // ═══════════════════════════════════════════════════════════════════
  // ROLE ASSIGNMENTS
  // ═══════════════════════════════════════════════════════════════════

  /**
   * GET /:did/members/:memberDid/roles
   * Get all roles assigned to a member.
   * If the request includes ?publicOnly=true, only returns visible roles.
   */
  router.get('/:did/members/:memberDid/roles', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const memberDid = decodeURIComponent(req.params.memberDid);
    try {
      const publicOnly = req.query.publicOnly === 'true';

      const assignments = await db
        .selectFrom('community_member_roles')
        .select(['role_name', 'assigned_by', 'created_at'])
        .where('community_did', '=', communityDid)
        .where('member_did', '=', memberDid)
        .execute();

      let roles = assignments;
      if (publicOnly) {
        // Filter to only roles marked as visible
        const visibleRoles = await db
          .selectFrom('community_roles')
          .select('name')
          .where('community_did', '=', communityDid)
          .where('visible', '=', true)
          .execute();
        const visibleSet = new Set(visibleRoles.map((r) => r.name));
        roles = assignments.filter((a) => visibleSet.has(a.role_name));
      }

      res.json({
        roles: roles.map((r) => ({
          roleName: r.role_name,
          assignedBy: r.assigned_by,
          assignedAt: r.created_at,
        })),
      });
    } catch (error) {
      logger.error({ error, communityDid, memberDid }, 'Error listing member roles');
      res.status(500).json({ error: 'Failed to list member roles' });
    }
  });

  /**
   * POST /:did/members/:memberDid/roles
   * Assign a role to a member (admin only).
   */
  router.post('/:did/members/:memberDid/roles', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const memberDid = decodeURIComponent(req.params.memberDid);
    let roleName: string | undefined;
    try {
      const parsed = assignRoleSchema.safeParse({ ...req.body, memberDid });
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid } = parsed.data;
      roleName = parsed.data.roleName;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      // Verify role exists (unless built-in)
      if (roleName !== 'admin' && roleName !== 'member') {
        const role = await db
          .selectFrom('community_roles')
          .select('id')
          .where('community_did', '=', communityDid)
          .where('name', '=', roleName)
          .executeTakeFirst();
        if (!role) {
          return res.status(404).json({ error: `Role "${roleName}" does not exist in this community` });
        }
      }

      // Check for duplicate assignment
      const existing = await db
        .selectFrom('community_member_roles')
        .select('id')
        .where('community_did', '=', communityDid)
        .where('member_did', '=', memberDid)
        .where('role_name', '=', roleName)
        .executeTakeFirst();
      if (existing) {
        return res.status(409).json({ error: `Member already has role "${roleName}"` });
      }

      await db
        .insertInto('community_member_roles')
        .values({
          community_did: communityDid,
          member_did: memberDid,
          role_name: roleName,
          assigned_by: adminDid,
        })
        .execute();

      // Invalidate role cache for this member
      memberRolesCache.invalidate(`${communityDid}:${memberDid}`);

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'role.assigned',
        targetDid: memberDid,
        metadata: { roleName },
      });

      res.status(201).json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid, memberDid, roleName }, 'Error assigning role');
      res.status(500).json({ error: 'Failed to assign role' });
    }
  });

  /**
   * DELETE /:did/members/:memberDid/roles/:roleName
   * Revoke a role from a member (admin only).
   */
  router.delete('/:did/members/:memberDid/roles/:roleName', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    const communityDid = decodeURIComponent(req.params.did);
    const memberDid = decodeURIComponent(req.params.memberDid);
    const roleName = req.params.roleName;
    try {
      const parsed = revokeRoleSchema.safeParse({ ...req.body, memberDid, roleName });
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { adminDid } = parsed.data;

      if (!(await requireAdmin(communityDid, adminDid, res))) return;

      const result = await db
        .deleteFrom('community_member_roles')
        .where('community_did', '=', communityDid)
        .where('member_did', '=', memberDid)
        .where('role_name', '=', roleName)
        .executeTakeFirst();

      if (!result.numDeletedRows || result.numDeletedRows === 0n) {
        return res.status(404).json({ error: 'Role assignment not found' });
      }

      // Invalidate role cache for this member
      memberRolesCache.invalidate(`${communityDid}:${memberDid}`);

      await auditLog.log({
        communityDid,
        adminDid,
        action: 'role.revoked',
        targetDid: memberDid,
        metadata: { roleName },
      });

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, communityDid, memberDid, roleName }, 'Error revoking role');
      res.status(500).json({ error: 'Failed to revoke role' });
    }
  });

  return router;
}
