/**
 * VaultDB Centralized Configuration (Node.js)
 * 12-Factor compliant configuration reading from environment variables and .env
 */

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

dotenv.config({ path: path.join(rootDir, '.env') });

export const settings = {
  PROJECT_NAME: 'VaultDB (Node.js)',
  VERSION: '2.0.0',
  DESCRIPTION: 'Cryptographically Immutable Database Middleware with PostgreSQL & immudb',

  // PostgreSQL Business Database Configuration
  POSTGRES: {
    host: process.env.POSTGRES_HOST || '127.0.0.1',
    port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
    database: process.env.POSTGRES_DB || 'postgres',
    user: process.env.POSTGRES_USER || 'vault_user',
    password: process.env.POSTGRES_PASSWORD || 'vault123',
    adminUser: process.env.POSTGRES_ADMIN_USER || 'postgres',
    adminPassword: process.env.POSTGRES_ADMIN_PASSWORD || 'nimit8222',
    max: parseInt(process.env.POSTGRES_POOL_MAX || '10', 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  },

  // immudb Cryptographic Ledger Configuration
  IMMUDB: {
    host: process.env.IMMUDB_HOST || '127.0.0.1',
    port: parseInt(process.env.IMMUDB_PORT || '3322', 10),
    pgsqlPort: parseInt(process.env.IMMUDB_PGSQL_PORT || '5433', 10),
    database: process.env.IMMUDB_DATABASE || 'defaultdb',
    user: process.env.IMMUDB_USER || 'immudb',
    password: process.env.IMMUDB_PASSWORD || 'immudb',
    max: 5,
  },

  // API Server Configuration
  SERVER: {
    host: process.env.APP_HOST || '0.0.0.0',
    port: parseInt(process.env.APP_PORT || '8000', 10),
  },

  // Sensitive Field Names for PII Interception
  SENSITIVE_FIELDS: new Set([
    'ssn',
    'password',
    'pwd',
    'secret',
    'credit_card',
    'card_number',
    'cvv',
    'pin',
    'salary',
    'token',
    'auth_token'
  ]),

  // Default RBAC Permissions Matrix
  RBAC_MATRIX: {
    admin: {
      users: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DDL'],
      accounts: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DDL'],
      transactions: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DDL'],
      compliance_policies: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DDL'],
      audit_logs: ['SELECT']
    },
    employee: {
      accounts: ['SELECT'],
      transactions: ['SELECT', 'INSERT', 'UPDATE'],
      compliance_policies: ['SELECT'],
      audit_logs: []
    },
    writer: {
      accounts: ['SELECT', 'INSERT', 'UPDATE'],
      transactions: ['SELECT', 'INSERT', 'UPDATE'],
      compliance_policies: ['SELECT'],
      audit_logs: []
    },
    customer: {
      accounts: ['SELECT'],
      transactions: ['SELECT'],
      compliance_policies: ['SELECT'],
      audit_logs: []
    },
    reader: {
      accounts: ['SELECT'],
      transactions: ['SELECT'],
      compliance_policies: ['SELECT'],
      audit_logs: []
    },
    auditor: {
      users: ['SELECT'],
      accounts: ['SELECT'],
      transactions: ['SELECT'],
      compliance_policies: ['SELECT'],
      audit_logs: ['SELECT']
    }
  }
};
