const express  = require('express');
const puppeteer = require('puppeteer');
const { execFile } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { requireAuth: auth } = require('../middleware/auth');

const router = express.Router();

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
// Body: { html, filename?, password? }
router.post('/pdf', auth, async (req, res) => {
  const { html, password, filename } = req.body;
  if (!html) return res.status(400).json({ error: 'html required' });

  let browser;
  try {
    const launchOpts = {
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--single-process', '--no-zygote'],
    };
    if (process.env.PUPPETEER_EXECUTABLE_PATH) {
      launchOpts.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
    }
    browser = await puppeteer.launch(launchOpts);

    const page = await browser.newPage();
    await page.setViewport({ width: 1024, height: 1448, deviceScaleFactor: 1 });
    await page.setContent(html, { waitUntil: 'networkidle0', timeout: 30000 });

    const pdfBytes = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
      scale: 0.78,
    });

    await browser.close();
    browser = null;

    let finalBytes = pdfBytes;
    if (password?.trim()) {
      finalBytes = await encryptWithGs(pdfBytes, password.trim());
    }

    const safeName = (filename || 'report').replace(/[^a-z0-9_\-\s]/gi, '_');
    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${safeName}.pdf"`,
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
