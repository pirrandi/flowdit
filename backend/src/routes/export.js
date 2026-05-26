const express  = require('express');
const puppeteer = require('puppeteer-core');
const { execFile } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { requireAuth: auth, requireUser } = require('../middleware/auth');

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
  const { pageUrl, token, password, rptKey, rptData } = req.body;
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

    // Inject auth token + report data into localStorage before page loads
    await page.evaluateOnNewDocument((t, key, data) => {
      if (t)    localStorage.setItem('fd_access', t);
      if (key && data) localStorage.setItem(key, data);
    }, token || '', rptKey || '', rptData || '');

    await page.goto(pageUrl, { waitUntil: 'networkidle0', timeout: 30000 });

    // Wait for fonts and report content to be ready
    await page.evaluateHandle('document.fonts.ready');
    await page.waitForFunction(
      () => document.getElementById('report-preview')?.children.length > 0,
      { timeout: 15000 }
    );

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
// Body: { pageUrl, token, rptKey, rptData, filename? }
router.post('/docx', auth, requireUser, async (req, res) => {
  const { pageUrl, token, rptKey, rptData, filename: rawFilename } = req.body;
  if (!pageUrl) return res.status(400).json({ error: 'pageUrl required' });

  if (!findSoffice()) return res.status(500).json({ error: 'LibreOffice not installed on server' });

  const executablePath = findChrome();
  if (!executablePath) return res.status(500).json({ error: 'No Chromium/Chrome found on server' });

  const tmpId   = `rpt_${Date.now()}`;
  const tmpHtml = path.join(os.tmpdir(), `${tmpId}.html`);
  const tmpDir  = os.tmpdir();
  const tmpDocx = path.join(os.tmpdir(), `${tmpId}.docx`);

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath,
      headless: true,
      args: [
        '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
        '--disable-gpu', '--single-process', '--no-zygote',
        '--force-device-scale-factor=1',
      ],
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 794, height: 1123, deviceScaleFactor: 1 });

    await page.evaluateOnNewDocument((t, key, data) => {
      if (t)           localStorage.setItem('fd_access', t);
      if (key && data) localStorage.setItem(key, data);
    }, token || '', rptKey || '', rptData || '');

    await page.goto(pageUrl, { waitUntil: 'networkidle0', timeout: 30000 });
    await page.evaluateHandle('document.fonts.ready');
    await page.waitForFunction(
      () => document.getElementById('report-preview')?.children.length > 0,
      { timeout: 15000 }
    );

    // Apply print CSS (light theme / black text) before extracting HTML
    await page.emulateMediaType('print');

    // Extract the full rendered HTML of the report preview with all styles resolved
    const html = await page.evaluate(() => {
      const preview = document.getElementById('report-preview');
      if (!preview) return '';

      // Collect all resolved CSS rules (only those that apply to .rpt* classes)
      // Avoid @-rules that contain CSS vars — LibreOffice handles plain CSS fine
      const safeStyles = [];
      for (const sheet of document.styleSheets) {
        try {
          for (const rule of sheet.cssRules) {
            // Skip @media, @keyframes, @font-face — LO doesn't need them
            if (rule.type !== CSSRule.STYLE_RULE) continue;
            // Only keep rules that could affect report elements
            safeStyles.push(rule.cssText);
          }
        } catch {}
      }

      const styleBlock = safeStyles.join('\n');
      return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #111; background: #fff; margin: 2cm; }
h1 { font-size: 22pt; font-weight: bold; color: #111; }
h2 { font-size: 14pt; font-weight: bold; color: #222; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 24pt; }
h3 { font-size: 12pt; font-weight: bold; color: #222; margin-top: 16pt; }
p, li { font-size: 11pt; color: #333; line-height: 1.6; }
table { border-collapse: collapse; width: 100%; margin: 12pt 0; }
th { background: #f3f4f6; font-weight: bold; font-size: 10pt; padding: 6pt 8pt; border: 1px solid #e5e7eb; text-align: left; }
td { font-size: 10pt; padding: 6pt 8pt; border: 1px solid #e5e7eb; vertical-align: top; color: #333; }
${styleBlock}
</style>
</head>
<body>${preview.innerHTML}</body>
</html>`;
    });

    await browser.close();
    browser = null;

    // Write HTML to temp file and convert with LibreOffice
    fs.writeFileSync(tmpHtml, html, 'utf8');
    await convertHtmlToDocx(tmpHtml, tmpDir);

    const docxBytes = fs.readFileSync(tmpDocx);
    const filename  = (rawFilename || 'report').replace(/[^a-z0-9_\-. ]/gi, '_');

    res.set({
      'Content-Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'Content-Disposition': `attachment; filename="${filename}.docx"`,
      'Content-Length': docxBytes.length,
    });
    res.end(docxBytes);

  } catch (err) {
    if (browser) await browser.close().catch(() => {});
    console.error('DOCX export error:', err);
    res.status(500).json({ error: 'DOCX generation failed: ' + err.message });
  } finally {
    try { fs.unlinkSync(tmpHtml); } catch {}
    try { fs.unlinkSync(tmpDocx); } catch {}
  }
});

module.exports = router;
