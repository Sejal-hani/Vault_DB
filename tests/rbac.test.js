import { describe, it } from 'node:test';
import assert from 'node:assert';
import { RBACManager } from '../src/core/rbac.js';

describe('RBACManager Module', () => {
  const rbac = new RBACManager();

  it('should allow admin to execute any operation', () => {
    const res = rbac.checkAuthorization('admin', 'DROP', ['accounts']);
    assert.strictEqual(res.isAllowed, true);
  });

  it('should allow customer to SELECT from accounts', () => {
    const res = rbac.checkAuthorization('customer', 'SELECT', ['accounts']);
    assert.strictEqual(res.isAllowed, true);
  });

  it('should block customer from deleting from accounts', () => {
    const res = rbac.checkAuthorization('customer', 'DELETE', ['accounts']);
    assert.strictEqual(res.isAllowed, false);
    assert.ok(res.reason.includes('not permitted'));
  });

  it('should block non-admin from executing DDL', () => {
    const res = rbac.checkAuthorization('employee', 'DDL:DROP', ['transactions']);
    assert.strictEqual(res.isAllowed, false);
  });
});
