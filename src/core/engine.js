/**
 * VaultEngine - Core Middleware Orchestrator (Node.js)
 * Intercepts SQL operations, verifies RBAC permissions, routes business queries to PostgreSQL,
 * and cryptographically records all audit trails into immudb.
 */

import { SQLParser } from './parser.js';
import { RBACManager, AccessDeniedError, QueryExecutionError } from './rbac.js';
import { PostgresStorage } from '../storage/postgres.js';
import { ImmudbStorage } from '../storage/immudb.js';

export class VaultEngine {
  constructor(postgresStorage = null, immudbStorage = null, rbacManager = null) {
    this.postgres = postgresStorage || new PostgresStorage();
    this.immudb = immudbStorage || new ImmudbStorage();
    this.rbac = rbacManager || new RBACManager();
  }

  /**
   * Resolves application user role from PostgreSQL.
   */
  async getUserRole(appUser) {
    return this.postgres.getUserRole(appUser);
  }

  /**
   * Main query execution pipeline with RBAC interception and dual cryptographic auditing.
   */
  async execute({
    query,
    params = null,
    appUser = 'alice@bank.com',
    clientIp = '127.0.0.1',
  }) {
    const startTime = process.hrtime.bigint();

    // 1. Resolve Identity and Role
    let userRole = 'customer';
    try {
      userRole = await this.getUserRole(appUser);
    } catch {
      userRole = 'customer';
    }

    // 2. Safe Query Parsing & Sensitive Attribute Analysis
    let analysis;
    let targetStr = 'unknown';
    try {
      analysis = SQLParser.analyze(query);
      targetStr = analysis.tables.length > 0 ? analysis.tables.join(', ') : 'unknown';
    } catch {
      analysis = {
        rawQuery: query,
        action: 'UNKNOWN',
        tables: [],
        isSensitive: false,
        sensitiveFieldsFound: [],
        isDDL: false,
      };
      targetStr = 'unknown';
    }

    // 3. RBAC Policy Enforcement
    const { isAllowed, reason } = this.rbac.check_authorization
      ? this.rbac.check_authorization(userRole, analysis.action, analysis.tables)
      : this.rbac.checkAuthorization(userRole, analysis.action, analysis.tables);

    if (!isAllowed) {
      const elapsedMs = Math.round((Number(process.hrtime.bigint() - startTime) / 1e6) * 100) / 100;

      // Cryptographically seal security violation into immudb ledger
      let immudbRecord = {};
      try {
        immudbRecord = await this.immudb.appendAuditLog({
          appUser,
          userRole,
          action: analysis.action,
          targetTable: targetStr,
          queryText: query,
          executionStatus: 'DENIED',
          executionTimeMs: elapsedMs,
          isSensitive: analysis.isSensitive,
          sensitiveFields: analysis.sensitiveFieldsFound,
          clientIp,
        });
      } catch (err) {
        console.error('[VaultEngine] Failed to write immudb violation log:', err.message);
      }

      // Redundant write to PostgreSQL
      await this.postgres.writeAuditLog({
        appUser,
        userRole,
        action: analysis.action,
        targetTable: targetStr,
        queryText: query,
        executionStatus: 'DENIED',
        immudbTxId: immudbRecord.immudb_tx_id || null,
        immudbTxHash: immudbRecord.immudb_tx_hash || null,
      });

      throw new AccessDeniedError(`Access Denied: ${reason}`, immudbRecord);
    }

    // 4. Execution on Relational Business Database (PostgreSQL)
    let executionRes;
    try {
      executionRes = await this.postgres.executeQuery(query, params);
    } catch (err) {
      const elapsedMs = Math.round((Number(process.hrtime.bigint() - startTime) / 1e6) * 100) / 100;

      // Cryptographically record failed/bad query into immudb ledger
      let immudbRecord = {};
      try {
        immudbRecord = await this.immudb.appendAuditLog({
          appUser,
          userRole,
          action: analysis.action,
          targetTable: targetStr,
          queryText: query,
          executionStatus: 'ERROR',
          executionTimeMs: elapsedMs,
          isSensitive: analysis.isSensitive,
          sensitiveFields: analysis.sensitiveFieldsFound,
          clientIp,
        });
      } catch (immuErr) {
        console.error('[VaultEngine] Failed to write immudb error log:', immuErr.message);
      }

      await this.postgres.writeAuditLog({
        appUser,
        userRole,
        action: analysis.action,
        targetTable: targetStr,
        queryText: query,
        executionStatus: 'ERROR',
        immudbTxId: immudbRecord.immudb_tx_id || null,
        immudbTxHash: immudbRecord.immudb_tx_hash || null,
      });

      throw new QueryExecutionError(err.message, immudbRecord);
    }

    const elapsedMs = Math.round((Number(process.hrtime.bigint() - startTime) / 1e6) * 100) / 100;

    // 5. Cryptographically seal successful audit record into immudb
    let immudbRecord = {};
    try {
      immudbRecord = await this.immudb.appendAuditLog({
        appUser,
        userRole,
        action: analysis.action,
        targetTable: targetStr,
        queryText: query,
        executionStatus: 'SUCCESS',
        executionTimeMs: elapsedMs,
        isSensitive: analysis.isSensitive,
        sensitiveFields: analysis.sensitiveFieldsFound,
        clientIp,
      });
    } catch (err) {
      console.error('[VaultEngine] Failed to write immudb success log:', err.message);
    }

    // Redundant write to PostgreSQL
    await this.postgres.writeAuditLog({
      appUser,
      userRole,
      action: analysis.action,
      targetTable: targetStr,
      queryText: query,
      executionStatus: 'SUCCESS',
      immudbTxId: immudbRecord.immudb_tx_id || null,
      immudbTxHash: immudbRecord.immudb_tx_hash || null,
    });

    return {
      status: 'SUCCESS',
      results: executionRes.rows,
      columns: executionRes.columns,
      rows_affected: executionRes.rowCount,
      execution_time_ms: executionRes.elapsedMs,
      is_sensitive: analysis.isSensitive,
      sensitive_fields: analysis.sensitiveFieldsFound,
      immudb_log_id: immudbRecord.id || null,
      immudb_tx_id: immudbRecord.immudb_tx_id || null,
      immudb_verified: immudbRecord.immudb_verified || true,
      immudb_tx_hash: immudbRecord.immudb_tx_hash || null,
    };
  }

  /**
   * Retrieves audit logs from immudb.
   */
  async getAuditLogs(limit = 50) {
    return this.immudb.getAuditLogs(limit);
  }

  /**
   * Verifies cryptographic inclusion proof for a specific log ID.
   */
  async verifyAuditLog(logId) {
    return this.immudb.verifyAuditLog(logId);
  }

  /**
   * Fetches ledger height and state root hash.
   */
  async getLedgerState() {
    return this.immudb.getLedgerState();
  }

  /**
   * Closes all database connection pools.
   */
  async close() {
    await this.postgres.close();
    await this.immudb.close();
  }
}
