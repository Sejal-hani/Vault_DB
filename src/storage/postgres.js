/**
 * PostgreSQL Storage Driver (Node.js)
 * Manages connection pooling, parameterized query execution,
 * and user role resolution for VaultDB business tables.
 */

import pg from 'pg';
import { settings } from '../../config/settings.js';

const { Pool } = pg;

export class PostgresStorage {
  constructor(customConfig = null) {
    const config = customConfig || settings.POSTGRES;
    this.pool = new Pool({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      max: config.max || 10,
      idleTimeoutMillis: config.idleTimeoutMillis || 30000,
      connectionTimeoutMillis: config.connectionTimeoutMillis || 5000,
    });

    // Handle pool errors gracefully without crashing process
    this.pool.on('error', (err) => {
      console.error('[PostgresStorage] Unexpected error on idle client:', err.message);
    });
  }

  /**
   * Performs health check against PostgreSQL instance.
   */
  async healthCheck() {
    try {
      const res = await this.pool.query('SELECT 1 as healthy;');
      return res.rows[0]?.healthy === 1;
    } catch (err) {
      console.error('[PostgresStorage] Health check failed:', err.message);
      return false;
    }
  }

  /**
   * Resolves the authenticated user's role from app_data.users table.
   * Defaults to 'customer' if not registered.
   */
  async getUserRole(email) {
    if (!email) return 'customer';
    try {
      const query = 'SELECT role FROM app_data.users WHERE email = $1 LIMIT 1;';
      const res = await this.pool.query(query, [email.trim().toLowerCase()]);
      if (res.rows.length > 0 && res.rows[0].role) {
        return res.rows[0].role.toLowerCase();
      }
    } catch (err) {
      console.warn(`[PostgresStorage] Could not resolve role for ${email}: ${err.message}`);
    }
    return 'customer';
  }

  /**
   * Executes a business SQL query with timing and row count metadata.
   */
  async executeQuery(queryText, params = null) {
    const start = process.hrtime.bigint();
    const client = await this.pool.connect();
    try {
      const res = await client.query(queryText, params || undefined);
      const end = process.hrtime.bigint();
      const elapsedMs = Number(end - start) / 1e6;

      const columns = res.fields ? res.fields.map((f) => f.name) : [];
      const rows = res.rows.map((row) => columns.map((col) => row[col]));

      return {
        rows,
        columns,
        rowCount: res.rowCount || rows.length,
        elapsedMs: Math.round(elapsedMs * 100) / 100,
      };
    } finally {
      client.release();
    }
  }

  /**
   * Writes a redundant copy of the audit log record to PostgreSQL vault_audit schema.
   */
  async writeAuditLog({
    appUser,
    userRole,
    action,
    targetTable,
    queryText,
    executionStatus,
    immudbTxId = null,
    immudbTxHash = null,
  }) {
    const sql = `
      INSERT INTO vault_audit.audit_logs 
        (app_user, user_role, action, target_table, query_text, execution_status, immudb_tx_id, immudb_tx_hash)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING log_id;
    `;
    try {
      const res = await this.pool.query(sql, [
        appUser,
        userRole,
        action,
        targetTable,
        queryText,
        executionStatus,
        immudbTxId,
        immudbTxHash,
      ]);
      return res.rows[0]?.log_id;
    } catch (err) {
      console.warn(`[PostgresStorage] Redundant audit write failed: ${err.message}`);
      return null;
    }
  }

  /**
   * Retrieves schema tables and row counts for Schema Explorer.
   */
  async getTables() {
    const sql = `
      SELECT table_name, table_schema
      FROM information_schema.tables
      WHERE table_schema = 'app_data'
      ORDER BY table_name;
    `;
    const res = await this.pool.query(sql);
    const tables = [];

    for (const row of res.rows) {
      try {
        const countRes = await this.pool.query(
          `SELECT COUNT(*)::int as cnt FROM ${row.table_schema}.${row.table_name};`
        );
        tables.push({
          name: row.table_name,
          schema: row.table_schema,
          rowCount: countRes.rows[0]?.cnt || 0,
        });
      } catch {
        tables.push({
          name: row.table_name,
          schema: row.table_schema,
          rowCount: 0,
        });
      }
    }
    return tables;
  }

  /**
   * Fetches paginated sample rows for a specific table with total row count and pagination metadata.
   */
  async getTableData(tableName, limit = 50, offset = 0) {
    const cleanTable = tableName.replace(/[^a-zA-Z0-9_]/g, '');
    const countRes = await this.pool.query(`SELECT COUNT(*)::int as cnt FROM app_data.${cleanTable};`);
    const totalCount = countRes.rows[0]?.cnt || 0;

    const sql = `SELECT * FROM app_data.${cleanTable} ORDER BY 1 LIMIT $1 OFFSET $2;`;
    const res = await this.pool.query(sql, [limit, offset]);
    const columns = res.fields ? res.fields.map((f) => f.name) : [];
    const rows = res.rows.map((row) => columns.map((col) => row[col]));
    return {
      tableName: `app_data.${cleanTable}`,
      columns,
      rows,
      limit,
      offset,
      totalRows: rows.length,
      totalCount,
      page: Math.floor(offset / limit) + 1,
      totalPages: Math.ceil(totalCount / limit) || 1,
    };
  }

  async close() {
    await this.pool.end();
  }
}
