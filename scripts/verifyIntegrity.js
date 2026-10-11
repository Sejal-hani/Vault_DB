/**
 * VaultDB CLI Verification Tool (Node.js)
 * Audits all logs in immudb, mathematically verifies SHA-256 hashes against
 * the Merkle state root, and generates a compliance verification report.
 */

import { ImmudbStorage } from '../src/storage/immudb.js';

async function verifyAll() {
  console.log('='.repeat(70));
  console.log(' VaultDB Cryptographic Ledger Audit Verification');
  console.log('='.repeat(70));

  const immudb = new ImmudbStorage();
  try {
    const state = await immudb.getLedgerState();
    console.log(`[i] Current Ledger Height: #${state.tx_id}`);
    console.log(`[i] State Merkle Root:     ${state.root_hash}`);
    console.log('-'.repeat(70));

    const logs = await immudb.getAuditLogs(100);
    if (logs.length === 0) {
      console.log('[*] No logs recorded in immudb yet.');
      return;
    }

    let verifiedCount = 0;
    let tamperedCount = 0;

    for (const log of logs) {
      const proof = await immudb.verifyAuditLog(log.id);
      if (proof.verified) {
        verifiedCount++;
        console.log(`[PASS] Tx #${log.immudb_tx_id.toString().padEnd(4)} | Log #${log.id.toString().padEnd(4)} | ${log.user.padEnd(20)} | ${log.status.padEnd(7)} | Hash: ${proof.record.entry_hash || 'AUTHENTIC'}`);
      } else {
        tamperedCount++;
        console.error(`[FAIL] Tx #${log.immudb_tx_id} | TAMPERING DETECTED! ${proof.message}`);
      }
    }

    console.log('='.repeat(70));
    console.log(`Total Audited:  ${logs.length}`);
    console.log(`Authentic (OK): ${verifiedCount}`);
    console.log(`Tampered/Error: ${tamperedCount}`);

    if (tamperedCount === 0) {
      console.log('[SUCCESS] All audit logs are cryptographically verified and untampered!');
    } else {
      console.error('[ALERT] Cryptographic integrity verification failed for one or more records!');
      process.exit(1);
    }
  } finally {
    await immudb.close();
  }
}

verifyAll().catch((err) => {
  console.error('Audit verification error:', err);
  process.exit(1);
});
