const express  = require('express');
const puppeteer = require('puppeteer-core');
const { execFile } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { requireAuth: auth, requireUser } = require('../middleware/auth');
const db   = require('../db');
const { generateDocx } = require('../services/docxExport');
const { findProjectForUser, isLeadRole } = require('../middleware/project');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Exporting the report hands the client deliverable out, so it is a lead-only
// (owner/editor) action — a pentester can work on the findings but not ship
// them. Answers { project } when the caller may export, else { status, error }.
async function checkExportAccess(projectId, userId) {
  if (!projectId) return { status: 400, error: 'projectId required' };
  if (!UUID_RE.test(String(projectId))) return { status: 404, error: 'Project not found' };
  const project = await findProjectForUser(projectId, userId);
  if (!project) return { status: 404, error: 'Project not found' };
  if (!isLeadRole(project.member_role))
    return { status: 403, error: 'Only the project owner or an editor can export the report' };
  return { project };
}

const router = express.Router();

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

function isExecutable(p) {
  try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
}

function findChrome() {
  // Explicit override wins — a deployer knows their binary better than we do.
  const override = process.env.PUPPETEER_EXECUTABLE_PATH || process.env.CHROME_BIN;
  if (override && isExecutable(override)) return override;
  return CHROME_CANDIDATES.find(isExecutable);
}

// SECURITY: pageUrl is browser-supplied (window.location.href), so it is
// attacker-controlled. Handing it to page.goto() unchanged made this endpoint a
// full-read SSRF: any authenticated user could point it at an internal service
// (cloud metadata, an admin panel) and get the rendered page back as a PDF.
//
// So the client's origin is never trusted. Only the path and query survive; the
// scheme/host always come from configuration, and the path must resolve to the
// export page itself. new URL() normalises "..", so traversal cannot walk out.
//
// INTERNAL_APP_URL takes precedence because Puppeteer runs inside the backend
// container, where "localhost" is the backend itself and not the nginx
// container serving the frontend. FRONTEND_URL is the bare-metal fallback.
// With neither configured there is no trusted origin to rebuild against, so the
// export fails closed rather than fetching whatever the caller asked for.
function resolveInternalPageUrl(pageUrl) {
  const base = process.env.INTERNAL_APP_URL || process.env.FRONTEND_URL;
  if (!base) {
    throw new Error(
      'Refusing to render: neither INTERNAL_APP_URL nor FRONTEND_URL is set, ' +
      'so there is no trusted origin to render the report from. See .env.example.'
    );
  }

  let requested;
  try { requested = new URL(pageUrl); }
  catch { throw new Error('pageUrl is not a valid URL'); }

  // Deployments under a sub-path keep their prefix, hence the suffix match.
  const cleanPath = requested.pathname.replace(/\/+$/, '');
  if (!/\/export(\.html)?$/.test(cleanPath)) {
    throw new Error('Refusing to render: only the export page can be rendered as a report');
  }

  const out    = new URL(base);
  out.pathname = requested.pathname;
  out.search   = requested.search;
  out.hash     = '';
  return out.toString();
}

// Password protection is done by Ghostscript. It is an optional feature: the
// unprotected PDF renders fine without it, so we only need `gs` when the caller
// actually asks for a password. Resolved the same way as Chrome — env override
// first, then the usual install locations — so a missing `gs` becomes one clear,
// actionable error instead of a generic ENOENT 500.
const GS_CANDIDATES = [
  '/usr/bin/gs',
  '/usr/local/bin/gs',
  '/opt/homebrew/bin/gs',
  '/snap/bin/gs',
  '/bin/gs',
];

function findGhostscript() {
  const override = process.env.GHOSTSCRIPT_BIN;
  if (override && isExecutable(override)) return override;
  return GS_CANDIDATES.find(isExecutable);
}

function encryptWithGs(pdfBytes, password, gsBin) {
  return new Promise((resolve, reject) => {
    const tmpIn  = path.join(os.tmpdir(), `rpt_${Date.now()}_in.pdf`);
    const tmpOut = path.join(os.tmpdir(), `rpt_${Date.now()}_out.pdf`);
    fs.writeFileSync(tmpIn, Buffer.from(pdfBytes));
    execFile(gsBin, [
      '-dBATCH', '-dNOPAUSE', '-sDEVICE=pdfwrite',
      '-dCompatibilityLevel=1.4',
      `-sOwnerPassword=${password}_owner`,
      `-sUserPassword=${password}`,
      '-dEncryptionR=3', '-dKeyLength=128',
      `-sOutputFile=${tmpOut}`,
      tmpIn,
    ], (err) => {
      try { fs.unlinkSync(tmpIn); } catch {}
      if (err) { try { fs.unlinkSync(tmpOut); } catch {}; return reject(err); }
      const result = fs.readFileSync(tmpOut);
      try { fs.unlinkSync(tmpOut); } catch {}
      resolve(result);
    });
  });
}

// POST /api/export/pdf
// Body: { pageUrl, projectId, token, password? }
router.post('/pdf', auth, requireUser, async (req, res) => {
  const { pageUrl, projectId, token, password, rptKey, rptData, scope, reportType, filename } = req.body;
  if (!pageUrl) return res.status(400).json({ error: 'pageUrl required' });

  // Resolved before the browser launches so a rejected URL costs nothing and
  // answers 400 (caller's fault) instead of the generic 500 below.
  let internalPageUrl;
  try { internalPageUrl = resolveInternalPageUrl(pageUrl); }
  catch (err) { return res.status(400).json({ error: err.message }); }

  try {
    const access = await checkExportAccess(projectId, req.user.id);
    if (!access.project) return res.status(access.status).json({ error: access.error });
  } catch (err) {
    console.error('PDF export access check failed:', err);
    return res.status(500).json({ error: 'PDF generation failed' });
  }

  const executablePath = findChrome();
  if (!executablePath) return res.status(500).json({
    error: 'No Chromium/Chrome found on server. Install a Chromium-based browser ' +
           '(chromium, google-chrome, brave, edge or vivaldi) or set ' +
           'PUPPETEER_EXECUTABLE_PATH to its binary.',
  });

  // If a password was requested, make sure we can actually honor it BEFORE
  // spending seconds rendering. Failing loudly (not returning an unprotected
  // PDF) is deliberate: the user asked for protection and must not be handed a
  // file they'd wrongly believe is encrypted.
  const wantsPassword = !!password?.trim();
  const gsBin = wantsPassword ? findGhostscript() : null;
  if (wantsPassword && !gsBin) return res.status(501).json({
    error: 'Password protection requires Ghostscript (gs) on the server, which is ' +
           'not installed. Install it (Arch: "sudo pacman -S ghostscript", ' +
           'Debian/Ubuntu: "sudo apt install ghostscript") or set GHOSTSCRIPT_BIN ' +
           'to its path — or export without a password.',
  });

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath,
      headless: true,
      // NOTE: no --single-process / --no-zygote. They save a few processes but
      // are notoriously fragile — they segfault (core dump) on several
      // Chromium builds, including Vivaldi, right after DevTools comes up,
      // which surfaces to the client as "socket hang up". Stability wins.
      args: [
        '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
        '--disable-gpu',
        '--force-device-scale-factor=1',
        '--font-render-hinting=none',
        '--disable-font-subpixel-positioning',
      ],
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 794, height: 1123, deviceScaleFactor: 1 });

    // Pin the API base before config.js's dev/prod hostname heuristic runs — the
    // page is navigated through the internal nginx hostname (see
    // resolveInternalPageUrl), which that heuristic doesn't recognize.
    // Puppeteer's browser runs inside the backend container itself, so its own
    // "localhost:4000" reaches this same process.
    await page.evaluateOnNewDocument(() => {
      window.FLOWDIT_API = 'http://localhost:4000/api';
      window.FLOWDIT_WS  = 'ws://localhost:4000/ws';
    });

    // Inject auth token + report data into localStorage before page loads.
    // FLOWDIT_SNAPSHOT tells export.html that this localStorage snapshot is the
    // authoritative copy for this render, so it must not pull the (possibly
    // older, debounce-behind) server copy over it — see pullReportConfig().
    await page.evaluateOnNewDocument((t, key, data) => {
      window.FLOWDIT_SNAPSHOT = true;
      if (t)    localStorage.setItem('fd_access', t);
      if (key && data) localStorage.setItem(key, data);
    }, token || '', rptKey || '', rptData || '');

    await page.goto(internalPageUrl, { waitUntil: 'networkidle0', timeout: 30000 });

    // Wait for fonts and report content to be ready
    await page.evaluateHandle('document.fonts.ready');
    await page.waitForFunction(
      () => document.getElementById('report-preview')?.children.length > 0,
      { timeout: 15000 }
    );

    // The fresh page always boots with the default scope/report-type — replay
    // whatever the originating tab had selected, then wait for the rebuild.
    if (scope || reportType) {
      await page.evaluate((s, rt) => {
        const preview = document.getElementById('report-preview');
        if (preview) preview.dataset.rendered = 'false';
        if (s) {
          const el = document.getElementById('export-scope');
          if (el) { el.value = s; el.dispatchEvent(new Event('change', { bubbles: true })); }
        }
        if (rt) {
          const el = document.getElementById('report-type');
          if (el) { el.value = rt; el.dispatchEvent(new Event('change', { bubbles: true })); }
        }
      }, scope || '', reportType || '');
      await page.waitForFunction(
        () => document.getElementById('report-preview')?.dataset.rendered === 'true',
        { timeout: 15000 }
      );
    }

    // Switch to print media after JS has built the layout
    await page.emulateMediaType('print');

    // Explicitly hide UI chrome and fix layout via JS
    await page.evaluate(() => {
      ['.sidenav','#sidenav','.topbar','#topbar','.exp-editor','.export-controls','.no-print','.toast-container','#loading-overlay']
        .forEach(sel => document.querySelectorAll(sel).forEach(el => el.style.setProperty('display','none','important')));
      document.body.style.cssText = 'display:block!important;margin:0!important;padding:0!important;overflow:visible!important;';
      ['.app-main','.exp-outer','.exp-inner','.exp-layout'].forEach(sel => {
        const el = document.querySelector(sel);
        if (el) el.style.cssText = 'display:block!important;margin:0!important;padding:0!important;width:100%!important;height:auto!important;overflow:visible!important;';
      });
      const prev = document.querySelector('.exp-preview');
      if (prev) prev.style.cssText = 'display:block!important;padding:0!important;width:100%!important;overflow:visible!important;height:auto!important;';
    });

    // Wait for all evidence images (base64 data URLs) to fully decode before PDF capture.
    // img.complete is true immediately for data URLs, but decode() resolves only after
    // the image has been decoded and is ready to paint.
    await page.evaluate(() => Promise.all(
      Array.from(document.images).map(img =>
        img.decode ? img.decode().catch(() => {}) : Promise.resolve()
      )
    ));
    // Force a layout reflow to flush paint before PDF capture
    await page.evaluate(() => void document.body.getBoundingClientRect());

    // Chrome writes document.title into the PDF's /Title, and that is what a
    // reader sees in their viewer's tab and window bar. Left alone it is this
    // app's own page title ("Export Report"), which says nothing about the
    // document. Use the report's cover title, falling back to the project name.
    const pageTitle = await page.evaluate(() => {
      const pick = v => (typeof v === 'string' ? v.trim() : '');
      try {
        return pick(getReportData()?.meta?.coverTitle) || pick(state?.currentProject?.name);
      } catch { return ''; }
    });
    const pdfTitle = (pageTitle || String(filename || '').trim() || 'Report').slice(0, 200);
    await page.evaluate(t => { document.title = t; }, pdfTitle);

    const pdfBytes = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
    });

    await browser.close();
    browser = null;

    let finalBytes = pdfBytes;
    if (wantsPassword) {
      finalBytes = await encryptWithGs(pdfBytes, password.trim(), gsBin);
    }

    // Same name in the header as in the PDF's own title. The quoted form must
    // stay plain ASCII with no quotes or CR/LF (header injection); filename*
    // carries the real, accented one for clients that understand RFC 5987.
    const asciiName = pdfTitle.normalize('NFKD')
      .replace(/[^\x20-\x7E]/g, '').replace(/["\\\r\n]/g, '')
      .trim().slice(0, 120) || 'report';
    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition':
        `attachment; filename="${asciiName}.pdf"; ` +
        `filename*=UTF-8''${encodeURIComponent(pdfTitle)}.pdf`,
      'Content-Length': finalBytes.length,
    });
    res.end(Buffer.from(finalBytes));

  } catch (err) {
    if (browser) await browser.close().catch(() => {});
    console.error('PDF export error:', err);
    res.status(500).json({ error: 'PDF generation failed: ' + err.message });
  }
});


// POST /api/export/docx
// Body: { projectId, type, rptData, filename? }
router.post('/docx', auth, requireUser, async (req, res) => {
  const { projectId, type = 'technical', rptData, filename: rawFilename } = req.body;

  try {
    // Verify project access + lead role (same resolution as requireProjectAccess)
    const access = await checkExportAccess(projectId, req.user.id);
    if (!access.project) return res.status(access.status).json({ error: access.error });
    const { project } = access;

    // Parse report metadata + sections from localStorage snapshot
    let meta = {}, sections = [];
    try {
      const parsed = JSON.parse(rptData || '{}');
      meta     = parsed.meta     || {};
      sections = parsed.sections || [];
    } catch {}

    // Fetch vulns (ordered by severity)
    const { rows: vulns } = await db.query(
      `SELECT cv.*, t.host AS target_host
       FROM custom_vulns cv
       LEFT JOIN targets t ON t.id = cv.target_id
       WHERE cv.project_id = $1
       ORDER BY
         CASE cv.severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
           WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6
         END, cv.created_at`,
      [projectId]
    );

    // Fetch targets
    const { rows: targets } = await db.query(
      `SELECT * FROM targets WHERE project_id = $1 ORDER BY created_at`,
      [projectId]
    );

    // Fetch ports for all targets
    const { rows: ports } = await db.query(
      `SELECT tp.* FROM target_ports tp
       JOIN targets t ON t.id = tp.target_id
       WHERE t.project_id = $1
       ORDER BY t.host, tp.port`,
      [projectId]
    );

    // Fetch WSTG progress (only rows with a status)
    const { rows: wstgProgress } = await db.query(
      `SELECT * FROM wstg_progress WHERE project_id = $1 AND status IS NOT NULL ORDER BY test_id`,
      [projectId]
    );

    const buffer = await generateDocx({
      project, vulns, targets, ports, wstgProgress,
      meta, type, sections,
    });

    const filename = (rawFilename || project.name || 'report').replace(/[^a-z0-9_\-. ]/gi, '_');
    res.set({
      'Content-Type':        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'Content-Disposition': `attachment; filename="${filename}.docx"`,
      'Content-Length':      buffer.length,
    });
    res.end(buffer);

  } catch (err) {
    console.error('DOCX export error:', err);
    res.status(500).json({ error: 'DOCX generation failed: ' + err.message });
  }
});

module.exports = router;
// Exported for the SSRF guard tests — asserting on the rebuilt URL directly is
// the only way to prove the caller's origin was discarded, since a legitimate
// path is rewritten rather than rejected and would otherwise need a browser.
module.exports.resolveInternalPageUrl = resolveInternalPageUrl;
