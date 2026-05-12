const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ── CONFIG ────────────────────────────────────────────────────────────────────

const PORT    = process.env.PORT       || 3001;
const API_KEY = process.env.AG_API_KEY || 'AetherGuardKey';
const STORAGE = fs.existsSync('/app/storage')
  ? '/app/storage'
  : path.join(__dirname, 'data');

if (!fs.existsSync(STORAGE)) fs.mkdirSync(STORAGE, { recursive: true });

// ── KEY DEFINITIONS ───────────────────────────────────────────────────────────

const MASTER_KEY  = 'AGUARD-MASTER-4CVP-AYSZ-2K7H';
const TESTER_KEYS = new Set([
  'AGUARD-TEST-3UYT-99XL-6KYQ-D9Z8',
  'AGUARD-TEST-66L9-RTX7-P9XV-ENN4',
  'AGUARD-TEST-Y8N7-PXHN-6DVC-RWKH',
  'AGUARD-TEST-Q722-K66E-WV8S-DZMZ',
  'AGUARD-TEST-EC2Q-WASG-ZGNG-L94X',
]);

// ── STORAGE HELPERS ───────────────────────────────────────────────────────────

function storePath(name) { return path.join(STORAGE, name); }

function loadJSON(name, fallback) {
  const p = storePath(name);
  if (!fs.existsSync(p)) return fallback !== undefined ? fallback : {};
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback !== undefined ? fallback : {}; }
}

function saveJSON(name, data) {
  fs.writeFileSync(storePath(name), JSON.stringify(data, null, 2));
}

// ── HTTP HELPERS ──────────────────────────────────────────────────────────────

function respond(res, status, body) {
  res.writeHead(status, {
    'Content-Type':                 'application/json',
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-API-Key, X-Device-ID',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  res.end(JSON.stringify(body));
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end',  () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

function authCheck(req, res) {
  if (req.headers['x-api-key'] !== API_KEY) {
    respond(res, 401, { error: 'Unauthorised.' });
    return false;
  }
  return true;
}

// ── KEY HELPERS ───────────────────────────────────────────────────────────────

function keyType(key) {
  if (key === MASTER_KEY)   return 'master';
  if (TESTER_KEYS.has(key)) return 'tester';
  const keys = loadJSON('keys.json', {});
  return keys[key]?.type || null;
}

function isKeyValid(key) {
  if (key === MASTER_KEY)   return { valid: true, type: 'master' };
  if (TESTER_KEYS.has(key)) return { valid: true, type: 'tester' };
  const keys = loadJSON('keys.json', {});
  const k    = keys[key];
  if (!k) return { valid: false, reason: 'Unknown key.' };
  if (k.type === 'monthly') {
    const expires = new Date(k.expiresAt).getTime() + 3 * 86400000;
    if (Date.now() > expires) return { valid: false, reason: 'Subscription expired.' };
  }
  return { valid: true, type: k.type, expiresAt: k.expiresAt };
}

function deviceCount(key) {
  const devices = loadJSON('devices.json', {});
  return (devices[key] || []).length;
}

function deviceAllowed(key, fingerprint) {
  if (keyType(key) === 'master') return true;
  const devices = loadJSON('devices.json', {});
  const list    = devices[key] || [];
  if (list.includes(fingerprint)) return true;
  return list.length < 3;
}

function registerDevice(key, fingerprint) {
  const devices = loadJSON('devices.json', {});
  if (!devices[key]) devices[key] = [];
  if (!devices[key].includes(fingerprint)) {
    devices[key].push(fingerprint);
    saveJSON('devices.json', devices);
  }
}

// ── TRIAL HELPERS ─────────────────────────────────────────────────────────────

const TRIAL_DAYS = 14;

function trialStatus(fingerprint) {
  const trials = loadJSON('trials.json', {});
  const t      = trials[fingerprint];
  if (!t) return { status: 'new' };
  const expires  = new Date(t.startedAt).getTime() + TRIAL_DAYS * 86400000;
  if (Date.now() > expires) return { status: 'expired', startedAt: t.startedAt };
  const daysLeft = Math.ceil((expires - Date.now()) / 86400000);
  return { status: 'active', daysLeft, startedAt: t.startedAt };
}

function startTrial(fingerprint) {
  const trials = loadJSON('trials.json', {});
  if (trials[fingerprint]) return false;
  trials[fingerprint] = { startedAt: new Date().toISOString() };
  saveJSON('trials.json', trials);
  return true;
}

// ── TOKEN HELPERS ─────────────────────────────────────────────────────────────

function saveTokens(fingerprint, platform, tokens) {
  const all = loadJSON('tokens.json', {});
  if (!all[fingerprint]) all[fingerprint] = {};
  all[fingerprint][platform] = { ...tokens, updatedAt: new Date().toISOString() };
  saveJSON('tokens.json', all);
}

function getAllTokens(fingerprint) {
  const all = loadJSON('tokens.json', {});
  return all[fingerprint] || {};
}

// ── ALERT HELPERS ─────────────────────────────────────────────────────────────

function getAlerts(fingerprint) {
  const all = loadJSON('alerts.json', {});
  return all[fingerprint] || [];
}

function saveAlert(fingerprint, alert) {
  const all = loadJSON('alerts.json', {});
  if (!all[fingerprint]) all[fingerprint] = [];
  all[fingerprint].unshift({
    id:        crypto.randomUUID(),
    ...alert,
    read:      false,
    timestamp: new Date().toISOString(),
  });
  all[fingerprint] = all[fingerprint].slice(0, 50);
  saveJSON('alerts.json', all);
}

function markAlertRead(fingerprint, alertId) {
  const all = loadJSON('alerts.json', {});
  if (!all[fingerprint]) return;
  const a = all[fingerprint].find(x => x.id === alertId);
  if (a) { a.read = true; saveJSON('alerts.json', all); }
}

// ── VAULT TRANSFER HELPERS ────────────────────────────────────────────────────

function loadTransfers()      { return loadJSON('transfers.json', {}); }
function saveTransfers(d)     { saveJSON('transfers.json', d); }
function loadEmailAccounts()  { return loadJSON('accounts.json',  {}); }
function saveEmailAccounts(d) { saveJSON('accounts.json',  d); }

// ── REQUEST HANDLER ───────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {

  // CORS preflight
  if (req.method === 'OPTIONS') { respond(res, 204, {}); return; }

  const url   = new URL(req.url, 'http://localhost');
  const path_ = url.pathname;
  const fp    = req.headers['x-device-id'] || '';

  console.log(`${req.method} ${path_}`);

  // ── Health ────────────────────────────────────────────────────────────────
  if (path_ === '/' && req.method === 'GET') {
    respond(res, 200, { status: 'ok', service: 'AetherGuard', version: '1.0.0' });
    return;
  }

  // ── Trial ─────────────────────────────────────────────────────────────────
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
    respond(res, 200, { started, ...trialStatus(fp) });
    return;
  }

  // ── Keys ──────────────────────────────────────────────────────────────────
  if (path_ === '/key/validate' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { key, fingerprint } = body;
    if (!key || !fingerprint) { respond(res, 400, { error: 'key and fingerprint required.' }); return; }
    const validity = isKeyValid(key);
    if (!validity.valid) { respond(res, 200, { valid: false, reason: validity.reason }); return; }
    if (!deviceAllowed(key, fingerprint)) {
      respond(res, 200, { valid: false, reason: 'Device limit reached for this key.' }); return;
    }
    registerDevice(key, fingerprint);
    respond(res, 200, { valid: true, type: validity.type, expiresAt: validity.expiresAt || null, devices: deviceCount(key) });
    return;
  }

  if (path_ === '/key/generate' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    if (body.adminSecret !== (process.env.ADMIN_SECRET || 'AetherAdmin')) {
      respond(res, 403, { error: 'Forbidden.' }); return;
    }
    const chars     = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const seg       = n => Array.from({length:n}, () => chars[Math.floor(Math.random()*chars.length)]).join('');
    const key       = `AGUARD-${seg(4)}-${seg(4)}-${seg(4)}-${seg(4)}`;
    const type      = body.type || 'lifetime';
    const expiresAt = type === 'monthly' ? new Date(Date.now() + 30*86400000).toISOString() : null;
    const keys      = loadJSON('keys.json', {});
    keys[key]       = { type, createdAt: new Date().toISOString(), expiresAt };
    saveJSON('keys.json', keys);
    respond(res, 200, { key, type, expiresAt });
    return;
  }

  // ── Tokens ────────────────────────────────────────────────────────────────
  if (path_ === '/tokens' && req.method === 'GET') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    respond(res, 200, { tokens: getAllTokens(fp) });
    return;
  }

  if (path_ === '/tokens' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { platform, tokens } = body;
    if (!fp || !platform) { respond(res, 400, { error: 'Device ID and platform required.' }); return; }
    saveTokens(fp, platform, tokens);
    respond(res, 200, { ok: true });
    return;
  }

  // ── Alerts ────────────────────────────────────────────────────────────────
  if (path_ === '/alerts' && req.method === 'GET') {
    if (!authCheck(req, res)) return;
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    respond(res, 200, { alerts: getAlerts(fp) });
    return;
  }

  if (path_ === '/alerts/read' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    if (!fp) { respond(res, 400, { error: 'Device ID required.' }); return; }
    markAlertRead(fp, body.alertId);
    respond(res, 200, { ok: true });
    return;
  }

  if (path_ === '/alerts/push' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { fingerprint, platform, message } = body;
    if (!fingerprint || !platform || !message) {
      respond(res, 400, { error: 'fingerprint, platform, message required.' }); return;
    }
    saveAlert(fingerprint, { platform, message });
    respond(res, 200, { pushed: true });
    return;
  }

  // ── Vault: email registration ─────────────────────────────────────────────
  if (path_ === '/vault/register-email' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { key, email } = body;
    if (!key || !email) { respond(res, 400, { error: 'key and email required.' }); return; }
    const validity = isKeyValid(key);
    if (!validity.valid) { respond(res, 400, { error: 'Invalid key.' }); return; }
    if (validity.type === 'master' || validity.type === 'tester') {
      respond(res, 200, { ok: true, exempt: true }); return;
    }
    const accts = loadEmailAccounts();
    accts[key]  = { email: email.toLowerCase().trim(), registeredAt: new Date().toISOString() };
    saveEmailAccounts(accts);
    respond(res, 200, { ok: true });
    return;
  }

  // ── Vault: create transfer token ──────────────────────────────────────────
  if (path_ === '/vault/transfer/create' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { key, fingerprint } = body;
    if (!key || !fingerprint) { respond(res, 400, { error: 'key and fingerprint required.' }); return; }
    const validity = isKeyValid(key);
    if (!validity.valid) { respond(res, 400, { error: 'Invalid key.' }); return; }
    const trusted = validity.type === 'master' || validity.type === 'tester';
    if (!trusted) {
      const accts = loadEmailAccounts();
      if (!accts[key]) {
        respond(res, 400, { error: 'Register your email in Settings before exporting.', requiresRegistration: true });
        return;
      }
    }
    const token     = crypto.randomUUID() + '-' + crypto.randomBytes(8).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 3600000).toISOString();
    const transfers = loadTransfers();
    transfers[token] = {
      originKey:  key,
      originType: validity.type,
      fingerprint,
      expiresAt,
      used:       false,
      burned:     false,
      createdAt:  new Date().toISOString(),
    };
    saveTransfers(transfers);
    console.log(`⊹ Transfer token created — expires ${expiresAt}`);
    respond(res, 200, { token, expiresAt });
    return;
  }

  // ── Vault: validate transfer token ────────────────────────────────────────
  if (path_ === '/vault/transfer/validate' && req.method === 'POST') {
    if (!authCheck(req, res)) return;
    const body = await parseBody(req);
    const { token, destKey, destFingerprint } = body;
    if (!token || !destKey || !destFingerprint) {
      respond(res, 400, { error: 'token, destKey, destFingerprint required.' }); return;
    }

    const transfers = loadTransfers();
    const transfer  = transfers[token];

    function burnAndReject(reason) {
      if (transfers[token]) { transfers[token].burned = true; saveTransfers(transfers); }
      respond(res, 200, { valid: false, reason });
    }

    if (!transfer)        { burnAndReject('Invalid or expired transfer file.'); return; }
    if (transfer.burned)  { burnAndReject('This transfer file has already been invalidated.'); return; }
    if (transfer.used)    { transfers[token].burned = true; saveTransfers(transfers); burnAndReject('This transfer file has already been imported.'); return; }
    if (new Date() > new Date(transfer.expiresAt)) { burnAndReject('This transfer file has expired (24-hour limit).'); return; }

    const destValidity = isKeyValid(destKey);
    if (!destValidity.valid) { burnAndReject('Destination license key is invalid.'); return; }

    const originTrusted = transfer.originType === 'master' || transfer.originType === 'tester';
    const destTrusted   = destValidity.type   === 'master' || destValidity.type   === 'tester';

    if (!originTrusted || !destTrusted) {
      const accts       = loadEmailAccounts();
      const originEmail = accts[transfer.originKey]?.email;
      const destEmail   = accts[destKey]?.email;
      if (!originEmail || !destEmail || originEmail !== destEmail) {
        burnAndReject('License keys are not registered to the same account.'); return;
      }
    }

    transfers[token].used       = true;
    transfers[token].destKey    = destKey;
    transfers[token].importedAt = new Date().toISOString();
    saveTransfers(transfers);
    console.log('⊹ Transfer validated successfully');
    respond(res, 200, { valid: true, originType: transfer.originType });
    return;
  }

  // ── 404 ───────────────────────────────────────────────────────────────────
  respond(res, 404, { error: 'Not found.', path: path_ });
});

server.listen(PORT, () => {
  console.log(`⊹ AetherGuard backend listening on port ${PORT}`);
});

// ── PLATFORM MONITOR ──────────────────────────────────────────────────────────

try {
  const { runMonitor } = require('./monitor');

  async function scheduledMonitor() {
    try { await runMonitor(getAllTokens, saveAlert, saveTokens); }
    catch (err) { console.warn('Monitor error:', err.message); }
  }

  scheduledMonitor();
  setInterval(scheduledMonitor, 5 * 60 * 1000);
  console.log('⊹ Platform monitor active — polling every 5 minutes.');
} catch (err) {
  console.warn('Monitor module not available:', err.message);
}
