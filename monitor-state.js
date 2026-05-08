// Tracks which device fingerprints have linked platforms
// so the monitor knows who to poll

const fs   = require('fs');
const path = require('path');

const STORAGE = fs.existsSync('/app/storage') ? '/app/storage' : path.join(__dirname, 'data');

function getAllDevices() {
  const p = path.join(STORAGE, 'tokens.json');
  if (!fs.existsSync(p)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(p, 'utf8'));
    return Object.keys(data);
  } catch { return []; }
}

module.exports = { getAllDevices };
