const fs = require('fs');

// Any Chromium-based browser drives Puppeteer, so the list stays broad on
// purpose: distro Chrome/Chromium, Brave, Edge and Vivaldi across the common
// install locations (Arch, Debian, snap, /opt vendor dirs). Deployers whose
// binary lives elsewhere set PUPPETEER_EXECUTABLE_PATH (or CHROME_BIN) and
// skip the guessing entirely.
const CHROME_CANDIDATES = [
  '/opt/brave-bin/brave',
  '/usr/bin/brave',
  '/usr/bin/brave-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
  '/usr/bin/microsoft-edge',
  '/usr/bin/microsoft-edge-stable',
  '/opt/vivaldi/vivaldi',
  '/usr/bin/vivaldi',
  '/usr/bin/vivaldi-stable',
];

// NOTE: no --single-process / --no-zygote. They save a few processes but are
// notoriously fragile — they segfault on several Chromium builds (Vivaldi
// included) right after DevTools comes up, which surfaces as "socket hang up".
const CHROME_ARGS = [
  '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
  '--disable-gpu',
  '--force-device-scale-factor=1',
  '--font-render-hinting=none',
  '--disable-font-subpixel-positioning',
];

function isExecutable(p) {
  try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
}

function findChrome() {
  // Explicit override wins — a deployer knows their binary better than we do.
  const override = process.env.PUPPETEER_EXECUTABLE_PATH || process.env.CHROME_BIN;
  if (override && isExecutable(override)) return override;
  return CHROME_CANDIDATES.find(isExecutable);
}

module.exports = { findChrome, isExecutable, CHROME_ARGS };
