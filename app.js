import express from 'express';
import { spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

if (!SECRET_KEY) {
  console.error('[ERROR] SECRET_KEY environment variable is not set. Exiting.');
  process.exit(1);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Set();

function stripAnsi(str) {
  return str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]/g, '');
}

function seedShellularConfig() {
  const hostId    = process.env.SHELLULAR_HOST_ID;
  const keyB64    = process.env.SHELLULAR_KEY;
  const machineId = process.env.SHELLULAR_MACHINE_ID;

  if (!hostId || !keyB64 || !machineId) return;

  // Only seed if the saved SHELLULAR_MACHINE_ID matches the actual machine ID.
  // If they differ (e.g. new build generated a different machine-id), skip seeding
  // so shellular registers fresh rather than failing with "Machine ID mismatch".
  const actualMachineId = getHashedMachineId();
  if (actualMachineId && actualMachineId !== machineId) {
    console.warn(`[shellular] machine-id mismatch — skipping seed (set MACHINE_ID_RAW to fix)`);
    return;
  }

  const shellularDir = path.join(os.homedir(), '.shellular');
  const configFile   = path.join(shellularDir, 'config.json');
  const keyFile      = path.join(shellularDir, `shellular-${machineId}.e2ee`);

  try {
    fs.mkdirSync(shellularDir, { recursive: true });
    if (!fs.existsSync(configFile)) {
      fs.writeFileSync(configFile, JSON.stringify({ hostId, machineId }), 'utf-8');
      console.log(`[shellular] seeded config: hostId=${hostId}`);
    }
    if (!fs.existsSync(keyFile)) {
      fs.writeFileSync(keyFile, Buffer.from(keyB64, 'base64'), { mode: 0o600 });
      console.log(`[shellular] seeded key: ${keyFile}`);
    }
  } catch (err) {
    console.error('[shellular] failed to seed config:', err.message);
  }
}

let generatedRawMachineId = null;

function getRawMachineId() {
  if (process.env.MACHINE_ID_RAW) return process.env.MACHINE_ID_RAW;

  try {
    return fs.readFileSync('/etc/machine-id', 'utf-8').trim();
  } catch {
    // No MACHINE_ID_RAW env var and no /etc/machine-id on this host (common on
    // some container platforms). Generate one so registration can still work,
    // and print it so it can be copied into a permanent MACHINE_ID_RAW secret —
    // otherwise a new random one is generated on every restart and you'll hit
    // "machine-id mismatch" / need to re-register each time.
    if (!generatedRawMachineId) {
      generatedRawMachineId = crypto.randomBytes(32).toString('hex');
      console.log('[shellular] No MACHINE_ID_RAW set and /etc/machine-id not found.');
      console.log('[shellular] Generated one for this session — set it as a permanent env var:');
      console.log(`[shellular]   MACHINE_ID_RAW=${generatedRawMachineId}`);
    }
    return generatedRawMachineId;
  }
}

function getHashedMachineId() {
  const raw = getRawMachineId();
  if (!raw) return null;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

seedShellularConfig();

app.get('/api/shellular/machine-id', (_req, res) => {
  const id = getHashedMachineId();
  id ? res.json({ machineId: id }) : res.status(500).json({ error: 'Cannot read machine-id' });
});

app.get('/api/shellular/raw-machine-id', (_req, res) => {
  const raw = getRawMachineId();
  raw ? res.json({ raw }) : res.status(500).json({ error: 'Not available' });
});

app.post('/api/shellular/seed-host', requireAuth, (req, res) => {
  const { hostId } = req.body || {};
  if (!hostId || typeof hostId !== 'string' || !hostId.trim()) {
    return res.status(400).json({ error: 'hostId is required' });
  }
  const machineId = getHashedMachineId();
  if (!machineId) return res.status(500).json({ error: 'Cannot read machine-id' });

  try {
    const shellularDir = path.join(os.homedir(), '.shellular');
    fs.mkdirSync(shellularDir, { recursive: true });
    fs.writeFileSync(
      path.join(shellularDir, 'config.json'),
      JSON.stringify({ hostId: hostId.trim(), machineId }, null, 2),
      'utf-8'
    );
    stopShellular();
    outputBuffer = '';
    broadcast({ type: 'clear' });
    setTimeout(startShellular, 600);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { key } = req.body;
  if (!key || key !== SECRET_KEY) {
    return res.status(401).json({ error: 'Invalid key' });
  }
  const token = crypto.randomUUID();
  sessions.add(token);
  res.json({ token });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  sessions.delete(token);
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

let shellularProc = null;
let outputBuffer  = '';
let retryTimer    = null;
const sseClients  = new Set();

function send(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcast(payload) {
  const frame = `data: ${JSON.stringify(payload)}\n\n`;
  for (const client of sseClients) {
    client.write(frame);
  }
}

function startShellular() {
  if (shellularProc || retryTimer) return;

  broadcast({ type: 'status', status: 'starting' });

  shellularProc = spawn('npx', ['shellular', '--unknown-clients', 'always-allow'], {
    env: { ...process.env, FORCE_COLOR: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let procOutput = '';

  const handleData = (chunk) => {
    const text = stripAnsi(chunk.toString());
    procOutput   += text;
    outputBuffer += text;
    broadcast({ type: 'output', text });
  };

  shellularProc.stdout.on('data', handleData);
  shellularProc.stderr.on('data', handleData);

  shellularProc.on('error', (err) => {
    const text = `\n[spawn error] ${err.message}\n`;
    outputBuffer += text;
    broadcast({ type: 'output', text });
    shellularProc = null;
    broadcast({ type: 'status', status: 'error' });
  });

  shellularProc.on('exit', (code, signal) => {
    shellularProc = null;

    const isMachineIdMismatch = procOutput.includes('Machine ID mismatch');
    const isRegError = code === 1 && !signal && !isMachineIdMismatch &&
      (procOutput.includes('invalid_union') || procOutput.includes('Too many requests') ||
       procOutput.includes('host registration'));

    if (isRegError) {
      const WAIT = 30;
      const msg = `\n⚠ Registration rate-limited by shellular API.\n  Retrying automatically in ${WAIT}s — please wait…\n`;
      outputBuffer += msg;
      broadcast({ type: 'output', text: msg });
      broadcast({ type: 'status', status: 'retrying' });

      retryTimer = setTimeout(() => {
        retryTimer = null;
        const msg2 = '\n[Retrying registration…]\n';
        outputBuffer += msg2;
        broadcast({ type: 'output', text: msg2 });
        startShellular();
      }, WAIT * 1000);
    } else {
      const text = code !== 0
        ? `\n[shellular exited — code=${code ?? '?'}, signal=${signal ?? 'none'}]\n`
        : '\n[shellular disconnected]\n';
      outputBuffer += text;
      broadcast({ type: 'output', text });
      broadcast({ type: 'status', status: 'stopped' });
    }
  });

  broadcast({ type: 'status', status: 'running' });
}

function stopShellular() {
  if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
  if (!shellularProc) return;
  shellularProc.kill('SIGTERM');
  shellularProc = null;
}

app.get('/api/stream', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  send(res, { type: 'status', status: shellularProc ? 'running' : 'stopped' });
  if (outputBuffer) send(res, { type: 'output', text: outputBuffer });

  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

app.post('/api/shellular/start', requireAuth, (_req, res) => {
  startShellular();
  res.json({ ok: true, running: !!shellularProc });
});

app.post('/api/shellular/stop', requireAuth, (_req, res) => {
  stopShellular();
  outputBuffer = '';
  broadcast({ type: 'output', text: '' });
  res.json({ ok: true });
});

app.post('/api/shellular/restart', requireAuth, (_req, res) => {
  stopShellular();
  outputBuffer = '';
  broadcast({ type: 'clear' });
  setTimeout(startShellular, 600);
  res.json({ ok: true });
});

app.get('/api/status', requireAuth, (_req, res) => {
  res.json({ running: !!shellularProc });
});

app.get('/api/setup-status', requireAuth, (_req, res) => {
  const seeded = !!(
    process.env.SHELLULAR_HOST_ID &&
    process.env.SHELLULAR_KEY &&
    process.env.SHELLULAR_MACHINE_ID &&
    process.env.MACHINE_ID_RAW
  );
  res.json({ seeded });
});

app.get('/api/shellular/credentials', requireAuth, (_req, res) => {
  try {
    const shellularDir = path.join(os.homedir(), '.shellular');
    const configRaw    = fs.readFileSync(path.join(shellularDir, 'config.json'), 'utf-8');
    const { hostId, machineId } = JSON.parse(configRaw);
    const keyFile = path.join(shellularDir, `shellular-${machineId}.e2ee`);
    const keyB64  = fs.readFileSync(keyFile).toString('base64');
    res.json({ hostId, machineId, keyB64 });
  } catch {
    res.status(404).json({ error: 'Not registered yet.' });
  }
});

app.get('/api/shellular/qr-data', requireAuth, (_req, res) => {
  try {
    const shellularDir = path.join(os.homedir(), '.shellular');
    const configRaw    = fs.readFileSync(path.join(shellularDir, 'config.json'), 'utf-8');
    const { hostId, machineId } = JSON.parse(configRaw);
    const keyFile = path.join(shellularDir, `shellular-${machineId}.e2ee`);
    const keyB64  = fs.readFileSync(keyFile).toString('base64');
    res.json({ qrData: `${hostId}:${keyB64}` });
  } catch {
    res.status(404).json({ error: 'Config not seeded yet.' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Shellular Web UI → http://0.0.0.0:${PORT}`);
});
