/**
 * Role-Based Access Control (RBAC) Module (Node.js)
 * Enforces table-level and operation-level policies based on authenticated user roles.
 */

import { settings } from '../../config/settings.js';

export class AccessDeniedError extends Error {
  constructor(message, immudbRecord = null) {
    super(message);
    this.name = 'AccessDeniedError';
    this.immudbRecord = immudbRecord || {};
  }
}

export class QueryExecutionError extends Error {
  constructor(message, immudbRecord = null) {
    super(message);
    this.name = 'QueryExecutionError';
    this.immudbRecord = immudbRecord || {};
  }
}

export class RBACManager {
  constructor(customMatrix = null) {
    this.matrix = customMatrix || settings.RBAC_MATRIX;
  }

  /**
   * Validates whether a user role is permitted to perform the specified action
   * across all detected target tables.
   */
  checkAuthorization(role, action, tables = []) {
    const normRole = (role || 'customer').toLowerCase();
    const permissions = this.matrix[normRole];

    if (!permissions) {
      return {
        isAllowed: false,
        reason: `Role '${normRole}' has no configured permissions in security policy.`,
      };
    }

    // Admins have unrestricted access
    if (normRole === 'admin') {
      return { isAllowed: true, reason: 'Admin role grants full system access.' };
    }

    // Block non-admin DDL attempts immediately
    if (action.startsWith('DDL:')) {
      return {
        isAllowed: false,
        reason: `Role '${normRole}' is strictly forbidden from executing DDL operations (${action}).`,
      };
    }

    // Default allowance if no tables are detected (e.g., SELECT 1; or SELECT NOW();)
    if (!tables || tables.length === 0) {
      return { isAllowed: true, reason: 'Non-table operational query allowed.' };
    }

    // Validate permission for each referenced table
    for (const table of tables) {
      const allowedActions = permissions[table];
      if (!allowedActions) {
        return {
          isAllowed: false,
          reason: `Role '${normRole}' is forbidden from accessing table '${table}'.`,
        };
      }

      if (!allowedActions.includes(action)) {
        return {
          isAllowed: false,
          reason: `Role '${normRole}' is not permitted to perform ${action} on table '${table}'. Allowed: [${allowedActions.join(', ')}].`,
        };
      }
    }

    return {
      isAllowed: true,
      reason: `Authorized: Role '${normRole}' has verified permissions for ${action} on [${tables.join(', ')}].`,
    };
  }
}
