/**
 * SQL Parser & Sensitive Attribute Inspector (Node.js)
 * Analyzes SQL AST and syntax for operational verbs, target tables,
 * and sensitive compliance fields (SSN, Passwords, Credit Cards).
 */

import { settings } from '../../config/settings.js';

const SQL_KEYWORDS = new Set([
  'select', 'from', 'where', 'join', 'into', 'table', 'update', 'set',
  'values', 'delete', 'insert', 'and', 'or', 'order', 'by', 'group', 'having',
  'limit', 'offset', 'as', 'on', 'inner', 'left', 'right', 'outer', 'cross',
  'create', 'drop', 'alter', 'truncate', 'primary', 'foreign', 'key'
]);

export class SQLParser {
  /**
   * Extracts the primary action / verb from a SQL query.
   */
  static extractAction(query) {
    if (!query) return 'UNKNOWN';
    const clean = query.replace(/--.*$/gm, '').trim().toUpperCase();

    const ddlVerbs = ['DROP', 'TRUNCATE', 'ALTER', 'CREATE'];
    for (const verb of ddlVerbs) {
      if (new RegExp(`^${verb}\\b`, 'i').test(clean)) {
        return `DDL:${verb}`;
      }
    }

    const dmlVerbs = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];
    for (const verb of dmlVerbs) {
      if (new RegExp(`^${verb}\\b`, 'i').test(clean)) {
        return verb;
      }
    }

    // Secondary scan within query
    for (const verb of ddlVerbs) {
      if (new RegExp(`\\b${verb}\\b`, 'i').test(clean)) return `DDL:${verb}`;
    }
    for (const verb of dmlVerbs) {
      if (new RegExp(`\\b${verb}\\b`, 'i').test(clean)) return verb;
    }

    return 'UNKNOWN';
  }

  /**
   * Identifies target tables affected or accessed by the query.
   */
  static extractTables(query) {
    if (!query) return [];
    const clean = query.replace(/--.*$/gm, '').trim();
    const tables = new Set();

    // Match FROM or JOIN patterns: FROM [schema.]table
    const fromJoinRegex = /\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+(?:([a-zA-Z0-9_]+)\.)?([a-zA-Z0-9_]+)/gi;
    let match;
    while ((match = fromJoinRegex.exec(clean)) !== null) {
      const tableName = match[2].toLowerCase();
      if (!SQL_KEYWORDS.has(tableName)) {
        tables.add(tableName);
      }
    }

    return Array.from(tables);
  }

  /**
   * Detects queries touching confidential or sensitive columns (SSN, passwords).
   */
  static inspectSensitiveColumns(query) {
    if (!query) return { isSensitive: false, sensitiveFieldsFound: [] };
    const clean = query.toLowerCase();
    const found = [];

    for (const field of settings.SENSITIVE_FIELDS) {
      const fieldRegex = new RegExp(`\\b${field}\\b`, 'i');
      if (fieldRegex.test(clean)) {
        found.push(field);
      }
    }

    return {
      isSensitive: found.length > 0,
      sensitiveFieldsFound: found,
    };
  }

  /**
   * Complete static query analysis pipeline.
   */
  static analyze(query) {
    const action = this.extractAction(query);
    const tables = this.extractTables(query);
    const { isSensitive, sensitiveFieldsFound } = this.inspectSensitiveColumns(query);

    return {
      rawQuery: query,
      action,
      tables,
      isSensitive,
      sensitiveFieldsFound,
      isDDL: action.startsWith('DDL:'),
    };
  }
}
