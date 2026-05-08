require('dotenv').config();
const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

// ── CONFIG ────────────────────────────────────────────────────────────────────

const CONFIG = {
  port:      process.env.PORT       || 3001,
  apiKey:    process.env.AG_API_KEY || 'AetherGuardKey',
  storage:   fs.existsSync('/app/storage') ? '/app/storage' : path.join(__dirname, 'data'),
};

if (!fs.existsSync(CONFIG.storage)) fs.mkdirSync(CONFIG.storage, { recursive: true });

// ── KEY DEFINITIONS ───────────────────────────────────────────────────────────

const MASTER_KEY   = 'AGUARD-MASTER-4CVP-AYSZ-2K7H';
const TESTER_KEYS  = new Set([
  'AGUARD-TEST-3UYT-99XL-6KYQ-D9Z8',
  'AGUARD-TEST-66L9-RTX7-P9XV-ENN4',
  'AGUARD-TEST-Y8N7-PXHN-6DVC-RWKH',
  'AGUARD-TEST-Q722-K66E-WV8S-DZMZ',
  'AGUARD-TEST-EC2Q-WASG-ZGNG-L94X',
]);

// ── STORAGE HELPERS ───────────────────────────────────────────────────────────

function storePath(name) { return path.join(CONFIG.storage, name); }

function loadJSON(name, fallback = {}) {
  const p = storePath(name);
  if (!fs.existsSync(p)) return fallback;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}

function saveJSON(name, data) {
  fs.writeFileSync(storePath(name), JSON.stringify(data, null, 2));
}

// ── KEY UTILITIES ─────────────────────────────────────────────────────────────

function genLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg   = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `AGUARD-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function keyType(key) {
  if (key === MASTER_KEY)      return 'master';
  if (TESTER_KEYS.has(key))   return 'tester';
  const keys = loadJSON('keys.json', {});
  if (!keys[key])              return null;
  return keys[key].tier; // 'monthly' | 'lifetime'
}

function isKeyValid(key) {
  const type = keyType(key);
  if (!type) return { valid: false, reason: 'Unknown key.' };
  if (type === 'master' || type === 'tester' || type === 'lifetime') {
    return { valid: true, type };
  }
  // Monthly — check expiry + grace
  const keys = loadJSON('keys.json', {});
  const k    = keys[key];
  const now  = Date.now();
  const grace = 3 * 24 * 60 * 60 * 1000; // 3 days
  if (now > new Date(k.expiresAt).getTime() + grace) {
    return { valid: false, reason: 'Subscription expired.', type };
  }
  return { valid: true, type, expiresAt: k.expiresAt };
}

function deviceCount(key) {
  const devices = loadJSON('devices.json', {});
  return (devices[key] || []).length;
}

function registerDevice(key, fingerprint) {
  const devices = loadJSON('devices.json', {});
  if (!devices[key]) devices[key] = [];
  if (!devices[key].includes(fingerprint)) {
    devices[key].push(fingerprint);
    saveJSON('devices.json', devices);
  }
}

function deviceAllowed(key, fingerprint) {
  const type = keyType(key);
  if (type === 'master') return true; // unlimited
  const devices = loadJSON('devices.json', {});
  const list    = devices[key] || [];
  if (list.includes(fingerprint)) return true; // already registered
  if (list.length >= 3) return false;          // limit reached
  return true;
}

// ── TRIAL HELPERS ─────────────────────────────────────────────────────────────

const TRIAL_DAYS = 14;

function trialStatus(fingerprint) {
  const trials = loadJSON('trials.json', {});
  const t      = trials[fingerprint];
  if (!t) return { status: 'new' };
  const now     = Date.now();
  const expires = new Date(t.startedAt).getTime() + TRIAL_DAYS * 24 * 60 * 60 * 1000;
  if (now > expires) return { status: 'expired', startedAt: t.startedAt };
  const daysLeft = Math.ceil((expires - now) / (24 * 60 * 60 * 1000));
  return { status: 'active', daysLeft, startedAt: t.startedAt };
}

function startTrial(fingerprint) {
  const trials = loadJSON('trials.json', {});
  if (trials[fingerprint]) return false; // already started
  trials[fingerprint] = { startedAt: new Date().toISOString() };
  saveJSON('trials.json', trials);
  return true;
}

// ── PLATFORM TOKEN STORAGE ────────────────────────────────────────────────────

function saveTokens(fingerprint, platform, tokens) {
  const all = loadJSON('tokens.json', {});
  if (!all[fingerprint]) all[fingerprint] = {};
  all[fingerprint][platform] = { ...tokens, updatedAt: new Date().toISOString() };
  saveJSON('tokens.json', all);
}

function getTokens(fingerprint, platform) {
  const all = loadJSON('tokens.json', {});
  return all[fingerprint]?.[platform] || null;
}

function getAllTokens(fingerprint) {
  const all = loadJSON('tokens.json', {});
  return all[fingerprint] || {};
}

// ── ALERT STORAGE ─────────────────────────────────────────────────────────────

function saveAlert(fingerprint, alert) {
  const alerts = loadJSON('alerts.json', {});
  if (!alerts[fingerprint]) alerts[fingerprint] = [];
  alerts[fingerprint].unshift({
    id:        crypto.randomUUID(),
    ...alert,
    timestamp: new Date().toISOString(),
    read:      false,
  });
  // Keep last 100 alerts per device
  alerts[fingerprint] = alerts[fingerprint].slice(0, 100);
  saveJSON('alerts.json', alerts);
}

function getAlerts(fingerprint) {
  const alerts = loadJSON('alerts.json', {});
  return alerts[fingerprint] || [];
}

function markAlertRead(fingerprint, alertId) {
  const alerts = loadJSON('alerts.json', {});
  if (!alerts[fingerprint]) return;
  const alert = alerts[fingerprint].find(a => a.id === alertId);
  if (alert) alert.read = true;
  saveJSON('alerts.json', alerts);
}

// ── HTTP SERVER ───────────────────────────────────────────────────────────────

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function respond(res, status, data) {
  res.writeHead(status, {
    'Content-Type':                'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods':'GET, POST, PATCH, OPTIONS',
    'Access-Control-Allow-Headers':'Content-Type, X-API-Key, X-Device-ID',
  });
  res.end(JSON.stringify(data));
}

function authCheck(req, res) {
  if (req.headers['x-api-key'] !== CONFIG.apiKey) {
    respond(res, 401, { error: 'Unauthorised.' });
    return false;
  }
  return true;
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { respond(res, 204, {}); return; }

  const url  = new URL(req.url, `http://localhost`);
  const path_ = url.pathname;
  const fp   = req.headers['x-device-id'] || '';

  // ── Health ──
  if (path_ === '/' && req.method === 'GET') {
    respond(res, 200, { status: 'ok', service: 'AetherGuard' });
    return;
  }

  // ── Trial: check / start ──
  if (path_ === '/trial' && req.method === 'GET') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    respond(res, 200, trialStatus(fp));
    return;
  }

  if (path_ === '/trial/start' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    const started = startTrial(fp);
    if (!started) {
      const status = trialStatus(fp);
      respond(res, 200, { started: false, ...status });
    } else {
      respond(res, 200, { started: true, ...trialStatus(fp) });
    }
    return;
  }

  // ── Key: validate + register device ──
  if (path_ === '/key/validate' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { key, fingerprint } = body;
    if (!key || !fingerprint) { respond(res, 400, { error: 'key and fingerprint required.' }); return; }

    const validity = isKeyValid(key);
    if (!validity.valid) { respond(res, 200, { valid: false, reason: validity.reason }); return; }

    if (!deviceAllowed(key, fingerprint)) {
      respond(res, 200, { valid: false, reason: 'Device limit reached. This key is active on 3 devices.' });
      return;
    }

    registerDevice(key, fingerprint);
    respond(res, 200, {
      valid:     true,
      type:      validity.type,
      expiresAt: validity.expiresAt || null,
      devices:   deviceCount(key),
    });
    return;
  }

  // ── Key: generate (for Stripe webhook / admin use) ──
  if (path_ === '/key/generate' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { tier, email } = body; // tier: 'monthly' | 'lifetime'
    if (!tier) { respond(res, 400, { error: 'tier required.' }); return; }

    const key     = genLicenseKey();
    const keys    = loadJSON('keys.json', {});
    const now     = new Date();
    const expires = tier === 'monthly'
      ? new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
      : null;

    keys[key] = {
      tier,
      email:     email || null,
      createdAt: now.toISOString(),
      expiresAt: expires,
    };
    saveJSON('keys.json', keys);
    console.log(`⊹ Key generated: ${key} (${tier}${email ? ' · ' + email : ''})`);
    respond(res, 200, { key, tier, expiresAt: expires });
    return;
  }

  // ── Key: renew monthly ──
  if (path_ === '/key/renew' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { key } = body;
    if (!key) { respond(res, 400, { error: 'key required.' }); return; }

    const keys = loadJSON('keys.json', {});
    if (!keys[key] || keys[key].tier !== 'monthly') {
      respond(res, 400, { error: 'Key not found or not a monthly key.' });
      return;
    }

    const now     = new Date();
    const current = new Date(keys[key].expiresAt);
    // Renew from current expiry if still valid, else from now
    const base    = current > now ? current : now;
    keys[key].expiresAt = new Date(base.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    saveJSON('keys.json', keys);
    respond(res, 200, { renewed: true, expiresAt: keys[key].expiresAt });
    return;
  }

  // ── Tokens: save ──
  if (path_ === '/tokens' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    const body = await parseBody(req);
    const { platform, tokens } = body;
    if (!platform || !tokens) { respond(res, 400, { error: 'platform and tokens required.' }); return; }
    saveTokens(fp, platform, tokens);
    respond(res, 200, { saved: true });
    return;
  }

  // ── Tokens: get all for device ──
  if (path_ === '/tokens' && req.method === 'GET') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    respond(res, 200, { tokens: getAllTokens(fp) });
    return;
  }

  // ── Alerts: get ──
  if (path_ === '/alerts' && req.method === 'GET') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    respond(res, 200, { alerts: getAlerts(fp) });
    return;
  }

  // ── Alerts: mark read ──
  if (path_ === '/alerts/read' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    const body = await parseBody(req);
    markAlertRead(fp, body.alertId);
    respond(res, 200, { ok: true });
    return;
  }

  // ── Alerts: push (internal — from platform monitor) ──
  if (path_ === '/alerts/push' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { fingerprint, platform, message } = body;
    if (!fingerprint || !platform || !message) {
      respond(res, 400, { error: 'fingerprint, platform, message required.' });
      return;
    }
    saveAlert(fingerprint, { platform, message });
    respond(res, 200, { pushed: true });
    return;
  }

  respond(res, 404, { error: 'Not found.' });
});

server.listen(CONFIG.port, () => {
  console.log(`⊹ AetherGuard backend listening on port ${CONFIG.port}.`);
});

// ── PLATFORM MONITOR SCHEDULER ────────────────────────────────────────────────
// Polls all connected accounts every 5 minutes

const { runMonitor } = require('./monitor');

async function scheduledMonitor() {
  try {
    await runMonitor(getAllTokens, saveAlert, saveTokens);
  } catch (err) {
    console.warn('Monitor run error:', err.message);
  }
}

// Run immediately on startup then every 5 minutes
scheduledMonitor();
setInterval(scheduledMonitor, 5 * 60 * 1000);

console.log('⊹ Platform monitor active — polling every 5 minutes.');
