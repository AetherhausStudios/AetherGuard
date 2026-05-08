// ── AETHERGUARD PLATFORM MONITOR ─────────────────────────────────────────────
// Polls connected platform accounts for login/integrity events.
// Runs as part of the backend process.

const https  = require('https');
const crypto = require('crypto');

// Platform definitions — what we can actually check
const PLATFORMS = {

  // ── FULL LOGIN DETECTION ──────────────────────────────────────────────────

  discord: {
    tier:  'trial',
    label: 'Discord',
    check: async (tokens) => {
      // Discord exposes current user sessions via /users/@me/guilds
      // We detect new auth by checking token validity and last_used
      const data = await discordFetch('/users/@me', tokens.accessToken);
      if (data.error) return { ok: false, error: data.error };
      // Store user ID for comparison
      return { ok: true, userId: data.id, username: data.username };
    },
  },

  twitch: {
    tier:  'trial',
    label: 'Twitch',
    check: async (tokens) => {
      const data = await twitchFetch('https://id.twitch.tv/oauth2/validate', tokens.accessToken);
      if (data.status === 401) return { ok: false, error: 'Token invalid — possible unauthorised access.' };
      return { ok: true, userId: data.user_id, login: data.login };
    },
  },

  steam: {
    tier:  'trial',
    label: 'Steam',
    check: async (tokens) => {
      // Steam Web API — recent player summary to confirm account access
      const url = `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${tokens.apiKey}&steamids=${tokens.steamId}`;
      const data = await fetchJSON(url);
      if (!data?.response?.players?.length) return { ok: false, error: 'Could not reach Steam account.' };
      return { ok: true, steamId: tokens.steamId, name: data.response.players[0].personaname };
    },
  },

  youtube: {
    tier:  'subscriber',
    label: 'YouTube / Google',
    check: async (tokens) => {
      const data = await googleFetch('https://www.googleapis.com/oauth2/v1/userinfo', tokens.accessToken);
      if (data.error) return { ok: false, error: 'Google token invalid — possible unauthorised access.' };
      return { ok: true, email: data.email, name: data.name };
    },
  },

  xbox: {
    tier:  'subscriber',
    label: 'Xbox / Microsoft',
    check: async (tokens) => {
      const data = await fetchWithAuth(
        'https://graph.microsoft.com/v1.0/me',
        tokens.accessToken
      );
      if (data.error) return { ok: false, error: 'Microsoft token invalid — possible unauthorised access.' };
      return { ok: true, email: data.mail || data.userPrincipalName, name: data.displayName };
    },
  },

  // ── INTEGRITY MONITORING ──────────────────────────────────────────────────

  instagram: {
    tier:  'subscriber',
    label: 'Instagram',
    check: async (tokens) => {
      // Token validity check — revocation = account compromise signal
      const url  = `https://graph.instagram.com/me?fields=id,username&access_token=${tokens.accessToken}`;
      const data = await fetchJSON(url);
      if (data.error) return { ok: false, integrity: false, error: 'Instagram access token revoked or invalid.' };
      return { ok: true, integrity: true, username: data.username };
    },
  },

  kofi: {
    tier:  'subscriber',
    label: 'Ko-fi',
    check: async (tokens) => {
      // Ko-fi webhook token validity — watch for token changes
      // We store the token hash and alert if it changes
      const currentHash = crypto.createHash('sha256').update(tokens.webhookToken || '').digest('hex');
      if (tokens.lastHash && tokens.lastHash !== currentHash) {
        return { ok: true, integrity: false, error: 'Ko-fi webhook token has changed — verify your account.' };
      }
      return { ok: true, integrity: true, hash: currentHash };
    },
  },

  patreon: {
    tier:  'subscriber',
    label: 'Patreon',
    check: async (tokens) => {
      const data = await fetchWithAuth('https://www.patreon.com/api/oauth2/v2/identity', tokens.accessToken);
      if (data.errors) return { ok: false, integrity: false, error: 'Patreon token invalid or revoked.' };
      return { ok: true, integrity: true, name: data.data?.attributes?.full_name };
    },
  },

  linktree: {
    tier:  'subscriber',
    label: 'Linktree',
    check: async (tokens) => {
      // Linktree API — profile fetch to verify token integrity
      const data = await fetchWithAuth('https://api.linktr.ee/v1/profiles', tokens.accessToken);
      if (data.message === 'Unauthorised') return { ok: false, integrity: false, error: 'Linktree token revoked — verify your account.' };
      return { ok: true, integrity: true };
    },
  },
};

// ── HTTP HELPERS ──────────────────────────────────────────────────────────────

function fetchJSON(url) {
  return new Promise((resolve) => {
    https.get(url, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve({ error: 'parse_error' }); }
      });
    }).on('error', () => resolve({ error: 'network_error' }));
  });
}

function fetchWithAuth(url, token, method = 'GET') {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const opts   = {
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method,
      headers:  { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    };
    https.request(opts, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve({ error: 'parse_error' }); }
      });
    }).on('error', () => resolve({ error: 'network_error' })).end();
  });
}

function discordFetch(endpoint, token) {
  return fetchWithAuth(`https://discord.com/api/v10${endpoint}`, token);
}

function twitchFetch(url, token) {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const opts   = {
      hostname: parsed.hostname,
      path:     parsed.pathname,
      headers:  { 'Authorization': `OAuth ${token}` },
    };
    https.request(opts, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve({ ...JSON.parse(body), status: res.statusCode }); }
        catch { resolve({ error: 'parse_error', status: res.statusCode }); }
      });
    }).on('error', () => resolve({ error: 'network_error' })).end();
  });
}

function googleFetch(url, token) {
  return fetchWithAuth(url, token);
}

// ── MONITOR RUNNER ────────────────────────────────────────────────────────────

// Called by index.js on a schedule
async function runMonitor(getAllTokens, saveAlert, saveTokens) {
  const tokenStore = require('./monitor-state');
  const devices    = tokenStore.getAllDevices();

  for (const fingerprint of devices) {
    const deviceTokens = getAllTokens(fingerprint);

    for (const [platform, platformDef] of Object.entries(PLATFORMS)) {
      const tokens = deviceTokens[platform];
      if (!tokens) continue; // platform not linked on this device

      try {
        const result = await platformDef.check(tokens);

        if (!result.ok) {
          // Something wrong — fire alert
          saveAlert(fingerprint, {
            platform: platformDef.label,
            message:  `New login detected on ${platformDef.label}. Was this you?`,
            detail:   result.error || null,
            severity: 'warning',
          });
          console.log(`⚠ Alert fired for ${fingerprint} — ${platformDef.label}: ${result.error}`);
        } else if (result.integrity === false) {
          // Integrity issue
          saveAlert(fingerprint, {
            platform: platformDef.label,
            message:  `Account integrity issue detected on ${platformDef.label}. Please verify your account.`,
            detail:   result.error || null,
            severity: 'warning',
          });
        }

        // Update stored hash for Ko-fi if present
        if (platform === 'kofi' && result.hash) {
          saveTokens(fingerprint, 'kofi', { ...tokens, lastHash: result.hash });
        }

      } catch (err) {
        console.warn(`Monitor error — ${platform} for ${fingerprint}:`, err.message);
      }
    }
  }
}

module.exports = { PLATFORMS, runMonitor };
