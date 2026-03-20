const express  = require('express');
const puppeteer = require('puppeteer-core');
const { execFile } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { requireAuth: auth } = require('../middleware/auth');

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
router.post('/pdf', auth, async (req, res) => {
  const { pageUrl, token, password, rptKey, rptData } = req.body;
  if (!pageUrl) return res.status(400).json({ error: 'pageUrl required' });

  const executablePath = findChrome();
  if (!executablePath) return res.status(500).json({ error: 'No Chromium/Chrome found on server' });

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote'],
    });

    const page = await browser.newPage();

    // Inject auth token + report data into localStorage before page loads
    await page.evaluateOnNewDocument((t, key, data) => {
      if (t)    localStorage.setItem('fd_access', t);
      if (key && data) localStorage.setItem(key, data);
    }, token || '', rptKey || '', rptData || '');

    await page.goto(pageUrl, { waitUntil: 'networkidle0', timeout: 30000 });

    // Wait for report content to be rendered
    await page.waitForFunction(
      () => document.getElementById('report-preview')?.children.length > 0,
      { timeout: 15000 }
    );

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

module.exports = router;
