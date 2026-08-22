const express  = require('express');
const puppeteer = require('puppeteer-core');
const { execFile } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { requireAuth: auth, requireUser } = require('../middleware/auth');
const db   = require('../db');
const { generateDocx } = require('../services/docxExport');

const router = express.Router();

const CHROME_CANDIDATES = [
  '/opt/brave-bin/brave',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
];

function findChrome() {
  return CHROME_CANDIDATES.find(p => {
    try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
  });
}

// Puppeteer runs inside the backend container, so the browser-supplied pageUrl
// (window.location.href, e.g. http://localhost/export?...) is not reachable from
// there — "localhost" resolves to the backend container itself, not the nginx
// container serving the frontend. INTERNAL_APP_URL lets ops point Puppeteer at
// the nginx service's internal address while keeping path/query intact.
function resolveInternalPageUrl(pageUrl) {
  if (!process.env.INTERNAL_APP_URL) return pageUrl;
  try {
    const url = new URL(pageUrl);
    const internal = new URL(process.env.INTERNAL_APP_URL);
    url.protocol = internal.protocol;
    url.host = internal.host;
    return url.toString();
  } catch {
    return pageUrl;
  }
}

const SOFFICE_CANDIDATES = [
  '/usr/bin/soffice',
  '/usr/bin/libreoffice',
  '/opt/libreoffice/program/soffice',
];

function findSoffice() {
  return SOFFICE_CANDIDATES.find(p => {
    try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
  });
}

function convertHtmlToDocx(htmlPath, outDir) {
  return new Promise((resolve, reject) => {
    const bin = findSoffice();
    if (!bin) return reject(new Error('LibreOffice not found on server'));
    execFile(bin, [
      '--headless',
      '--infilter=HTML (StarWriter)',
      '--convert-to', 'docx:MS Word 2007 XML',
      '--outdir', outDir,
      htmlPath,
    ], { timeout: 60000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      resolve();
    });
  });
}

function encryptWithGs(pdfBytes, password) {
  return new Promise((resolve, reject) => {
    const tmpIn  = path.join(os.tmpdir(), `rpt_${Date.now()}_in.pdf`);
    const tmpOut = path.join(os.tmpdir(), `rpt_${Date.now()}_out.pdf`);
    fs.writeFileSync(tmpIn, Buffer.from(pdfBytes));
    execFile('gs', [
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
// Body: { pageUrl, token, password? }
router.post('/pdf', auth, requireUser, async (req, res) => {
  const { pageUrl, token, password, rptKey, rptData, scope, reportType } = req.body;
  if (!pageUrl) return res.status(400).json({ error: 'pageUrl required' });

  const executablePath = findChrome();
  if (!executablePath) return res.status(500).json({ error: 'No Chromium/Chrome found on server' });

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath,
      headless: true,
      args: [
        '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
        '--disable-gpu', '--single-process', '--no-zygote',
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

    // Inject auth token + report data into localStorage before page loads
    await page.evaluateOnNewDocument((t, key, data) => {
      if (t)    localStorage.setItem('fd_access', t);
      if (key && data) localStorage.setItem(key, data);
    }, token || '', rptKey || '', rptData || '');

    await page.goto(resolveInternalPageUrl(pageUrl), { waitUntil: 'networkidle0', timeout: 30000 });

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

    const pdfBytes = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
    });

    await browser.close();
    browser = null;

    let finalBytes = pdfBytes;
    if (password?.trim()) {
      finalBytes = await encryptWithGs(pdfBytes, password.trim());
    }

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="report.pdf"`,
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
  if (!projectId) return res.status(400).json({ error: 'projectId required' });

  try {
    // Verify project access
    const { rows: projRows } = await db.query(
      `SELECT p.* FROM projects p
       JOIN project_members pm ON pm.project_id = p.id
       WHERE p.id = $1 AND pm.user_id = $2`,
      [projectId, req.user.id]
    );
    if (!projRows.length) return res.status(404).json({ error: 'Project not found' });
    const project = projRows[0];

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
