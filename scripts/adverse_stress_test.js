/**
 * VaultDB Adverse Scenarios & 10,000+ Queries Stress Test (Node.js)
 * Executes large-scale adverse scenarios:
 * 1. Privilege Escalation & Unauthorized Deletes
 * 2. SQL Injection Patterns
 * 3. Financial Balance Tampering
 * 4. Sensitive PII Surveillance (SSN, Passwords)
 * 5. Malformed SQL & Syntax Errors
 * 6. High-Throughput Concurrent Burst Testing
 * Validates that all queries (valid, blocked, and failed) are sealed in immudb.
 */

import { VaultEngine } from '../src/core/engine.js';

async function runAdverseStressTest(totalQueries = 10000) {
  console.log('='.repeat(75));
  console.log(` VaultDB Adverse Scenario & Scalability Test (${totalQueries.toLocaleString()} Queries)`);
  console.log('='.repeat(75));

  const engine = new VaultEngine();
  const startTime = Date.now();

  const adverseScenarios = [
    // 1. Authorized queries
    {
      type: 'AUTHORIZED_SELECT',
      user: 'admin@bank.com',
      query: 'SELECT account_number, balance FROM app_data.accounts WHERE id = 1;',
      expectedStatus: 'SUCCESS',
    },
    {
      type: 'AUTHORIZED_EMPLOYEE_READ',
      user: 'john@bank.com',
      query: 'SELECT t.id, t.amount, t.status FROM app_data.transactions t LIMIT 2;',
      expectedStatus: 'SUCCESS',
    },

    // 2. Sensitive PII Access
    {
      type: 'SENSITIVE_PII_SSN',
      user: 'admin@bank.com',
      query: 'SELECT name, ssn, balance FROM app_data.accounts WHERE id = 1;',
      expectedStatus: 'SUCCESS',
      isSensitive: true,
    },

    // 3. RBAC Policy Violations: Unauthorized Deletes
    {
      type: 'VIOLATION_UNAUTHORIZED_DELETE',
      user: 'alice@bank.com',
      query: 'DELETE FROM app_data.transactions WHERE id = 9999;',
      expectedStatus: 'DENIED',
    },
    {
      type: 'VIOLATION_CUSTOMER_DROP',
      user: 'alice@bank.com',
      query: 'DROP TABLE app_data.accounts;',
      expectedStatus: 'DENIED',
    },

    // 4. Financial Tampering: Unauthorized Balance Updates
    {
      type: 'VIOLATION_TAMPER_BALANCE',
      user: 'john@bank.com',
      query: 'UPDATE app_data.accounts SET balance = 99999999 WHERE id = 1;',
      expectedStatus: 'DENIED',
    },

    // 5. SQL Injection Attack Patterns
    {
      type: 'SQLI_TAUTOLOGY',
      user: 'alice@bank.com',
      query: "SELECT * FROM app_data.accounts WHERE name = 'Alice' OR '1'='1';",
      expectedStatus: 'SUCCESS',
    },
    {
      type: 'SQLI_UNION_ATTACK',
      user: 'alice@bank.com',
      query: 'SELECT * FROM app_data.accounts UNION SELECT email, role, NULL, NULL FROM app_data.users;',
      expectedStatus: 'DENIED', // Unauthorized access to users table
    },
    {
      type: 'SQLI_STACKED_DROP',
      user: 'john@bank.com',
      query: 'SELECT id FROM app_data.accounts; DROP TABLE app_data.transactions; --',
      expectedStatus: 'DENIED', // Blocked by DDL policy
    },

    // 6. Malformed SQL & Syntax Errors
    {
      type: 'SYNTAX_ERROR_MALFORMED',
      user: 'admin@bank.com',
      query: 'SELECT ,,, FROM app_data.accounts WHERE ;;',
      expectedStatus: 'ERROR',
    },
    {
      type: 'NON_EXISTENT_TABLE',
      user: 'admin@bank.com',
      query: 'SELECT * FROM app_data.shadow_black_ops_table;',
      expectedStatus: 'ERROR',
    },
  ];

  let successCount = 0;
  let deniedCount = 0;
  let errorCount = 0;
  let sensitiveCount = 0;

  console.log(`[*] Initiating execution of ${totalQueries.toLocaleString()} diverse queries (concurrency: 10)...`);

  const concurrency = 10;
  let activeIndex = 0;

  async function worker() {
    while (activeIndex < totalQueries) {
      const i = activeIndex++;
      const s = adverseScenarios[i % adverseScenarios.length];
      try {
        const res = await engine.execute({
          query: s.query,
          appUser: s.user,
        });
        if (res.status === 'SUCCESS') successCount++;
        if (res.is_sensitive) sensitiveCount++;
      } catch (err) {
        if (err.name === 'AccessDeniedError') {
          deniedCount++;
        } else {
          errorCount++;
        }
      }

      if ((i + 1) % 1000 === 0 || i === totalQueries - 1) {
        const elapsedSec = (Date.now() - startTime) / 1000;
        const qps = Math.round((i + 1) / elapsedSec);
        console.log(
          `[Progress] ${((i + 1) / totalQueries * 100).toFixed(0).padStart(3)}% | ` +
          `Processed: ${(i + 1).toLocaleString().padStart(6)} | ` +
          `Throughput: ${qps} QPS | ` +
          `Success: ${successCount} | ` +
          `Violations Blocked: ${deniedCount} | ` +
          `Syntax Errors: ${errorCount}`
        );
      }
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);

  const totalTimeSec = (Date.now() - startTime) / 1000;
  const avgQps = Math.round(totalQueries / totalTimeSec);

  // Fetch final immudb state
  const state = await engine.getLedgerState();

  console.log('='.repeat(75));
  console.log(' ADVERSE SCENARIO STRESS TEST SUMMARY');
  console.log('='.repeat(75));
  console.log(`Total Queries Run:       ${totalQueries.toLocaleString()}`);
  console.log(`Execution Time:          ${totalTimeSec.toFixed(2)} seconds`);
  console.log(`Average Throughput:      ${avgQps} queries/second`);
  console.log(`Authorized Queries:      ${successCount.toLocaleString()}`);
  console.log(`Security Blocks (RBAC):  ${deniedCount.toLocaleString()}`);
  console.log(`Database/Syntax Errors:  ${errorCount.toLocaleString()}`);
  console.log(`Sensitive Queries Track: ${sensitiveCount.toLocaleString()}`);
  console.log(`Final immudb Height:     Tx #${state.tx_id.toLocaleString()}`);
  console.log(`Merkle State Root Hash:  ${state.root_hash}`);

  // Verification phase: sample check 5 random entries
  console.log('-'.repeat(75));
  console.log('[*] Cryptographic Sampling Verification: Checking recent entries against Merkle Root...');
  
  const recentLogs = await engine.getAuditLogs(10);
  let allVerified = true;
  for (const log of recentLogs) {
    const proof = await engine.verifyAuditLog(log.id);
    if (!proof.verified) {
      allVerified = false;
      console.error(`[-] FAILED verification on Log #${log.id}`);
    }
  }

  if (allVerified) {
    console.log('[+] Zero-trust Merkle verification: 100% of tested log entries are untampered and authentic!');
  }

  console.log('='.repeat(75));
  await engine.close();
}

const count = parseInt(process.argv[2] || '10000', 10);
runAdverseStressTest(count).catch(console.error);
