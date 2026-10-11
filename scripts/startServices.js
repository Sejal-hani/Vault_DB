/**
 * VaultDB Service Launcher (Node.js)
 * Automatically ensures immudb server is running and launches the Express web studio.
 */

import net from 'net';
import path from 'path';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { settings } from '../config/settings.js';
import { startServer } from '../src/api/server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

function isPortInUse(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(800);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      resolve(false);
    });
    socket.connect(port, host);
  });
}

async function ensureImmudbRunning() {
  const isGrpcActive = await isPortInUse(settings.IMMUDB.port, settings.IMMUDB.host);
  const isPgsqlActive = await isPortInUse(settings.IMMUDB.pgsqlPort, settings.IMMUDB.host);

  if (isGrpcActive && isPgsqlActive) {
    console.log(`[+] immudb service is already active on ports ${settings.IMMUDB.port} (gRPC) & ${settings.IMMUDB.pgsqlPort} (pgsql).`);
    return null;
  }

  const binaryPath = path.join(rootDir, 'bin', 'immudb.exe');
  if (!fs.existsSync(binaryPath)) {
    console.warn(`[-] Warning: ${binaryPath} not found. Please ensure immudb server is running.`);
    return null;
  }

  const dataDir = path.join(rootDir, 'data', 'immudb');
  fs.mkdirSync(dataDir, { recursive: true });

  const args = [
    '--dir', dataDir,
    '--port', String(settings.IMMUDB.port),
    '--pgsql-server=true',
    '--pgsql-server-port', String(settings.IMMUDB.pgsqlPort),
    '--web-server=true',
    '--web-server-port', '3323',
  ];

  console.log(`[*] Launching immudb server (pgsql: ${settings.IMMUDB.pgsqlPort}, gRPC: ${settings.IMMUDB.port})...`);
  const proc = spawn(binaryPath, args, {
    detached: true,
    stdio: 'ignore',
  });
  proc.unref();

  // Wait for port to become active
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 400));
    const active = await isPortInUse(settings.IMMUDB.pgsqlPort, settings.IMMUDB.host);
    if (active) {
      console.log(`[+] immudb server started successfully.`);
      return proc;
    }
  }

  console.warn(`[-] immudb took longer than expected to bind to port ${settings.IMMUDB.pgsqlPort}.`);
  return proc;
}

async function main() {
  await ensureImmudbRunning();
  await startServer(settings.SERVER.port, settings.SERVER.host);
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
