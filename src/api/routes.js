/**
 * VaultDB API Routes (Node.js / Express)
 */

import express from 'express';
import { VaultEngine } from '../core/engine.js';
import { AccessDeniedError, QueryExecutionError } from '../core/rbac.js';
import { SQLParser } from '../core/parser.js';
import { generateAuditPdf } from '../reports/pdfGenerator.js';

export const router = express.Router();
const engine = new VaultEngine();

// Ensure immudb table is ready on startup
engine.immudb.init().catch((err) => {
  console.warn('[Routes] Immudb init warning:', err.message);
});

/**
 * POST /api/execute
 * Intercepts SQL query, checks RBAC, executes on Postgres, commits to immudb.
 */
router.post('/execute', async (req, res) => {
  const { user, query, params } = req.body;
  const clientIp = req.ip || req.socket?.remoteAddress || '127.0.0.1';

  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'Query parameter is required.' });
  }

  try {
    const result = await engine.execute({
      query,
      params,
      appUser: user || 'alice@bank.com',
      clientIp,
    });
    return res.json(result);
  } catch (err) {
    const analysis = SQLParser.analyze(query);
    const rec = err.immudbRecord || {};

    if (err instanceof AccessDeniedError) {
      return res.json({
        status: 'DENIED',
        error: err.message,
        rows_affected: 0,
        is_sensitive: analysis.isSensitive,
        sensitive_fields: analysis.sensitiveFieldsFound,
        immudb_log_id: rec.id || null,
        immudb_tx_id: rec.immudb_tx_id || null,
        immudb_verified: rec.immudb_verified || true,
        immudb_tx_hash: rec.immudb_tx_hash || null,
      });
    }

    if (err instanceof QueryExecutionError) {
      return res.json({
        status: 'ERROR',
        error: err.message,
        rows_affected: 0,
        is_sensitive: analysis.isSensitive,
        sensitive_fields: analysis.sensitiveFieldsFound,
        immudb_log_id: rec.id || null,
        immudb_tx_id: rec.immudb_tx_id || null,
        immudb_verified: rec.immudb_verified || true,
        immudb_tx_hash: rec.immudb_tx_hash || null,
      });
    }

    return res.status(500).json({
      status: 'ERROR',
      error: err.message,
      rows_affected: 0,
      is_sensitive: analysis.isSensitive,
      sensitive_fields: analysis.sensitiveFieldsFound,
    });
  }
});

/**
 * GET /api/logs
 * Retrieves immutable logs from immudb.
 */
router.get('/logs', async (req, res) => {
  const limit = parseInt(req.query.limit || '50', 10);
  try {
    const logs = await engine.getAuditLogs(limit);
    return res.json(logs);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/verify/:log_id
 * Performs zero-trust cryptographic proof verification.
 */
router.get('/verify/:log_id', async (req, res) => {
  const logId = parseInt(req.params.log_id, 10);
  try {
    const verification = await engine.verifyAuditLog(logId);
    return res.json(verification);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/ledger-state
 * Fetches current immudb ledger height and state root hash.
 */
router.get('/ledger-state', async (req, res) => {
  try {
    const state = await engine.getLedgerState();
    return res.json(state);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/health
 * System health status for PostgreSQL and immudb.
 */
router.get('/health', async (req, res) => {
  const [pgOk, immuOk] = await Promise.all([
    engine.postgres.healthCheck(),
    engine.immudb.healthCheck(),
  ]);

  return res.json({
    status: pgOk && immuOk ? 'healthy' : 'degraded',
    postgres: pgOk ? 'healthy' : 'unreachable',
    immudb: immuOk ? 'healthy' : 'unreachable',
    version: '2.0.0 (Node.js)',
  });
});

/**
 * GET /api/tables
 * Lists business tables in PostgreSQL.
 */
router.get('/tables', async (req, res) => {
  try {
    const tables = await engine.postgres.getTables();
    return res.json(tables);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/tables/:table_name
 * Browses sample rows from a table.
 */
router.get('/tables/:table_name', async (req, res) => {
  const tableName = req.params.table_name;
  const limit = parseInt(req.query.limit || '50', 10);
  try {
    const data = await engine.postgres.getTableData(tableName, limit);
    return res.json({
      table: tableName,
      columns: data.columns,
      rows: data.rows,
      total_rows_returned: data.totalRows,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/stats
 * Dashboard summary statistics.
 */
router.get('/stats', async (req, res) => {
  try {
    const [logs, state] = await Promise.all([
      engine.getAuditLogs(100),
      engine.getLedgerState(),
    ]);

    const totalAudited = logs.length;
    const successCount = logs.filter((l) => l.status === 'SUCCESS').length;
    const deniedCount = logs.filter((l) => l.status === 'DENIED').length;
    const sensitiveCount = logs.filter((l) => l.is_sensitive).length;

    return res.json({
      total_audited: totalAudited,
      success_count: successCount,
      denied_count: deniedCount,
      sensitive_count: sensitiveCount,
      ledger_height: state.tx_id,
      root_hash: state.root_hash,
      database: state.database,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/reports/pdf
 * Generates and downloads certified compliance audit PDF report.
 */
router.get('/reports/pdf', async (req, res) => {
  const { table, user, status } = req.query;
  try {
    const [allLogs, state] = await Promise.all([
      engine.getAuditLogs(100),
      engine.getLedgerState(),
    ]);

    const filtered = allLogs.filter((l) => {
      if (table && l.table !== table) return false;
      if (user && l.user !== user) return false;
      if (status && l.status !== status) return false;
      return true;
    });

    const pdfBuffer = await generateAuditPdf({
      logs: filtered,
      ledgerState: state,
      filters: { table, user, status },
    });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="vaultdb_compliance_report.pdf"');
    return res.send(pdfBuffer);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});
