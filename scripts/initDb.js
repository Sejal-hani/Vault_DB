/**
 * Database Initialization Script (Node.js)
 * Applies schemas and initial seed data to PostgreSQL and immudb.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import { settings } from '../config/settings.js';
import { ImmudbStorage } from '../src/storage/immudb.js';

const { Client } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

async function initPostgres() {
  console.log(`[*] Initializing PostgreSQL at ${settings.POSTGRES.host}:${settings.POSTGRES.port}...`);
  const schemaPath = path.join(rootDir, 'schema.sql');

  if (!fs.existsSync(schemaPath)) {
    console.error(`[-] Error: ${schemaPath} not found!`);
    return false;
  }

  const sql = fs.readFileSync(schemaPath, 'utf8');
  const client = new Client({
    host: settings.POSTGRES.host,
    port: settings.POSTGRES.port,
    database: settings.POSTGRES.database,
    user: settings.POSTGRES.adminUser,
    password: settings.POSTGRES.adminPassword,
  });

  try {
    await client.connect();
    await client.query(sql);
    console.log('[+] PostgreSQL schema and permissions successfully applied.');

    // Seed sample records if empty
    const checkRes = await client.query('SELECT COUNT(*)::int as count FROM app_data.users;');
    if (checkRes.rows[0].count === 0) {
      console.log('[*] Seeding sample users and accounts...');
      await client.query(`
        INSERT INTO app_data.users (email, full_name, role, department) VALUES
          ('admin@bank.com', 'Chief Security Officer', 'admin', 'Executive'),
          ('compliance.lead@bank.com', 'Helen Vance', 'auditor', 'Compliance'),
          ('sarah.auditor@bank.com', 'Sarah Lin', 'auditor', 'Regulatory Review'),
          ('john@bank.com', 'Johnathan Reed', 'employee', 'Branch Operations'),
          ('rachel.ops@bank.com', 'Rachel Green', 'employee', 'Risk Management'),
          ('alice@bank.com', 'Alice Smith', 'customer', 'Retail Banking'),
          ('carlos.m@techcorp.io', 'Carlos Mendez', 'customer', 'Commercial Treasury')
        ON CONFLICT (email) DO NOTHING;

        INSERT INTO app_data.accounts (id, account_number, name, account_type, ssn, balance) VALUES
          (1, 'ACC-1001', 'Alice Smith', 'Checking', '***-**-1234', 99999.00),
          (2, 'ACC-1002', 'Bob Johnson', 'Savings', '***-**-5678', 1250000.00),
          (3, 'ACC-1003', 'Carlos Mendez', 'Treasury', '***-**-9012', 4850000.00)
        ON CONFLICT (id) DO NOTHING;

        INSERT INTO app_data.compliance_policies (policy_code, title, standard, description) VALUES
          ('GDPR-ART30', 'Records of Processing Activities', 'GDPR', 'Mandatory tamper-proof logging of all data subject access events'),
          ('HIPAA-164.312', 'Audit Controls', 'HIPAA', 'Cryptographic hardware/software logging of electronic protected health information'),
          ('PCI-REQ10', 'Track and Monitor All Network Access', 'PCI-DSS', 'Log all individual access to cardholder data environments')
        ON CONFLICT (policy_code) DO NOTHING;
      `);
      console.log('[+] Sample data seeded successfully.');
    }

    return true;
  } catch (err) {
    console.error(`[-] PostgreSQL initialization failed: ${err.message}`);
    return false;
  } finally {
    await client.end().catch(() => {});
  }
}

async function initImmudb() {
  console.log(`[*] Connecting to immudb at ${settings.IMMUDB.host}:${settings.IMMUDB.pgsqlPort}...`);
  const immudb = new ImmudbStorage();
  try {
    await immudb.init();
    const state = await immudb.getLedgerState();
    console.log(`[+] immudb ledger ready! Database: ${state.database}, Current Tx: #${state.tx_id}`);
    console.log(`    Merkle State Root Hash: ${state.root_hash}`);
    await immudb.close();
    return true;
  } catch (err) {
    console.error(`[-] immudb connection failed: ${err.message}`);
    return false;
  }
}

async function main() {
  console.log('='.repeat(70));
  console.log(' VaultDB: Dual-Storage Initialization (Node.js)');
  console.log('='.repeat(70));

  const pgOk = await initPostgres();
  const immuOk = await initImmudb();

  console.log('='.repeat(70));
  if (pgOk && immuOk) {
    console.log('[SUCCESS] All database components are fully functioning and ready!');
  } else {
    console.warn('[WARNING] One or more components reported an issue.');
  }
  console.log('='.repeat(70));
}

main().catch(console.error);
