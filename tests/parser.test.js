import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SQLParser } from '../src/core/parser.js';

describe('SQLParser Module', () => {
  it('should extract SELECT verb accurately', () => {
    const action = SQLParser.extractAction('SELECT id, name FROM app_data.accounts;');
    assert.strictEqual(action, 'SELECT');
  });

  it('should extract DDL verbs like DROP and ALTER', () => {
    assert.strictEqual(SQLParser.extractAction('DROP TABLE users;'), 'DDL:DROP');
    assert.strictEqual(SQLParser.extractAction('ALTER TABLE accounts ADD COLUMN balance INT;'), 'DDL:ALTER');
  });

  it('should extract target table names', () => {
    const tables = SQLParser.extractTables('SELECT a.name, t.amount FROM app_data.accounts a JOIN app_data.transactions t ON a.id = t.account_id;');
    assert.ok(tables.includes('accounts'));
    assert.ok(tables.includes('transactions'));
  });

  it('should flag sensitive columns like SSN and password', () => {
    const ssnRes = SQLParser.inspectSensitiveColumns('SELECT name, ssn FROM app_data.accounts;');
    assert.strictEqual(ssnRes.isSensitive, true);
    assert.ok(ssnRes.sensitiveFieldsFound.includes('ssn'));

    const cleanRes = SQLParser.inspectSensitiveColumns('SELECT id, name, created_at FROM app_data.accounts;');
    assert.strictEqual(cleanRes.isSensitive, false);
    assert.strictEqual(cleanRes.sensitiveFieldsFound.length, 0);
  });
});
