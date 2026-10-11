/**
 * VaultDB Application Server (Node.js / Express)
 * Serves the REST API and the Enterprise Compliance Studio UI.
 */

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { settings } from '../../config/settings.js';
import { router as apiRouter } from './routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

export const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve API routes
app.use('/api', apiRouter);

// Serve Static Frontend Studio UI
const publicDir = path.join(rootDir, 'public');
const templatesDir = path.join(rootDir, 'templates');

app.use(express.static(publicDir));

app.get('/', (req, res) => {
  res.sendFile(path.join(templatesDir, 'index.html'));
});

// Swagger / Documentation redirect or info
app.get('/docs', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>VaultDB API Reference</title>
        <style>
          body { background: #09090b; color: #f4f4f5; font-family: -apple-system, sans-serif; padding: 40px; }
          pre { background: #18181b; padding: 20px; border-radius: 8px; border: 1px solid #27272a; color: #a1a1aa; }
          a { color: #60a5fa; text-decoration: none; }
        </style>
      </head>
      <body>
        <h2>VaultDB API Reference (Node.js Engine)</h2>
        <p>Return to <a href="/">Dashboard Studio</a></p>
        <pre>
POST /api/execute          - Execute query with RBAC & immudb commitment
GET  /api/logs             - Retrieve immutable audit ledger entries
GET  /api/verify/:log_id   - Cryptographically verify Merkle proof of entry
GET  /api/ledger-state     - Current state root hash and transaction height
GET  /api/health           - System health for PostgreSQL and immudb
GET  /api/tables           - List all tables in app_data schema
GET  /api/tables/:table    - Inspect sample table records
GET  /api/stats            - Aggregated audit statistics
GET  /api/reports/pdf      - Certified regulatory compliance PDF export
        </pre>
      </body>
    </html>
  `);
});

export function startServer(port = settings.SERVER.port, host = settings.SERVER.host) {
  return new Promise((resolve) => {
    const server = app.listen(port, host, () => {
      console.log('='.repeat(70));
      console.log(` VaultDB Enterprise (Node.js): Scalable Immutable Middleware`);
      console.log(` Version: ${settings.VERSION}`);
      console.log(` Web Studio UI: http://localhost:${port}`);
      console.log(` REST API Base: http://localhost:${port}/api`);
      console.log(` API Docs:      http://localhost:${port}/docs`);
      console.log('='.repeat(70));
      resolve(server);
    });
  });
}

// Auto-run when executed directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer();
}
