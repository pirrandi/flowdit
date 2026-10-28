// Image handling for the DOCX export: data-URL decoding, pixel sizes, format
// conversion and the watermark picture.
//
// Word embeds PNG/JPEG/GIF/BMP. Anything else (WebP logos, SVG) is redrawn to
// PNG by the headless Chromium the PDF export already uses, launched lazily
// once per export and only when something needs it. No Chromium on the box →
// those images are skipped and the document still renders.

/* global Image, document -- only inside page.evaluate(), which runs in Chromium */
const zlib = require('zlib');
const { findChrome, CHROME_ARGS } = require('../browser');

const MAX_DATA_URL = 24 * 1024 * 1024;   // ~18 MB decoded; bigger is refused
const MAX_PIXELS   = 2400;               // longer side above this is downscaled (when Chromium is around)
const NATIVE       = new Set(['png', 'jpg', 'gif', 'bmp']);

// ── Header sniffing ────────────────────────────────────────────────
function sniff(buf) {
  if (!buf || buf.length < 24) return null;
  // PNG
  if (buf.readUInt32BE(0) === 0x89504e47) {
    return { type: 'png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  }
  // GIF
  if (buf.toString('ascii', 0, 3) === 'GIF') {
    return { type: 'gif', width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) };
  }
  // BMP
  if (buf.toString('ascii', 0, 2) === 'BM' && buf.length >= 26) {
    return { type: 'bmp', width: buf.readInt32LE(18), height: Math.abs(buf.readInt32LE(22)) };
  }
  // JPEG: walk the markers to the first SOFn
  if (buf[0] === 0xff && buf[1] === 0xd8) {
    let i = 2;
    while (i + 9 < buf.length) {
      if (buf[i] !== 0xff) { i++; continue; }
      const marker = buf[i + 1];
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
      const len = buf.readUInt16BE(i + 2);
      if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
        return { type: 'jpg', height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
      }
      i += 2 + len;
    }
    return null;
  }
  // WebP (not embeddable, but its size is still useful)
  if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') {
    const chunk = buf.toString('ascii', 12, 16);
    if (chunk === 'VP8X') return { type: 'webp', width: 1 + buf.readUIntLE(24, 3), height: 1 + buf.readUIntLE(27, 3) };
    if (chunk === 'VP8 ') return { type: 'webp', width: buf.readUInt16LE(26) & 0x3fff, height: buf.readUInt16LE(28) & 0x3fff };
    if (chunk === 'VP8L') {
      const b = buf.readUInt32LE(21);
      return { type: 'webp', width: (b & 0x3fff) + 1, height: ((b >> 14) & 0x3fff) + 1 };
    }
    return { type: 'webp', width: 0, height: 0 };
  }
  return null;
}

function parseDataUrl(src) {
  if (typeof src !== 'string' || src.length > MAX_DATA_URL) return null;
  const m = /^data:([a-z0-9.+/-]+)?(;[^,]*)?,/i.exec(src.slice(0, 200));
  if (!m) return null;
  const isB64 = /;base64/i.test(m[2] || '');
  const body  = src.slice(m[0].length);
  try {
    const buf = isB64 ? Buffer.from(body, 'base64') : Buffer.from(decodeURIComponent(body), 'utf8');
    return { mime: (m[1] || '').toLowerCase(), buf };
  } catch { return null; }
}

// ── Tiny dependency-free PNG (used as the last-resort watermark fallback) ──
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td  = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function transparentPng() {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(1, 0); ihdr.writeUInt32BE(1, 4);
  ihdr[8] = 8; ihdr[9] = 6;   // 8-bit RGBA
  const raw = Buffer.from([0, 0, 0, 0, 0]);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr), pngChunk('IDAT', zlib.deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ── Watermark ──────────────────────────────────────────────────────
const xmlEsc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// Diagonal, light grey, same normalisation as the PDF's watermarkPngUri().
function watermarkSvg(text) {
  const raw = String(text || 'DRAFT').replace(/\p{Cc}/gu, '').trim().toUpperCase() || 'DRAFT';
  const BOX = 1000;
  // Courier-ish metrics: ~0.6em per glyph plus 0.15em tracking.
  const size = Math.max(28, Math.min(150, Math.floor((BOX * 1.25) / (raw.length * 0.75))));
  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${BOX}" height="${BOX}" viewBox="0 0 ${BOX} ${BOX}">`
    + `<text x="${BOX / 2}" y="${BOX / 2}" transform="rotate(-45 ${BOX / 2} ${BOX / 2})" text-anchor="middle" dominant-baseline="middle"`
    + ` font-family="Consolas, 'Courier New', monospace" font-weight="700" font-size="${size}" letter-spacing="${Math.round(size * 0.15)}"`
    + ` fill="#C8C8C8" fill-opacity="0.55">${xmlEsc(raw)}</text></svg>`, 'utf8');
}

// ── Store ──────────────────────────────────────────────────────────
class ImageStore {
  constructor() {
    this.pending = new Set();
    this.ready   = new Map();   // src → { data, type, width, height } | null
    this.browser = null;
    this.page    = null;
    this.browserFailed = false;
  }

  add(src) {
    if (typeof src === 'string' && src.startsWith('data:') && !this.ready.has(src)) this.pending.add(src);
  }

  // Every <img src="data:..."> inside an HTML fragment.
  addFromHtml(html) {
    if (typeof html !== 'string' || !html.includes('<img')) return;
    const re = /<img\b[^>]*?\bsrc\s*=\s*(["'])(data:[^"']+)\1/gi;
    let m;
    while ((m = re.exec(html))) this.add(m[2]);
  }

  get(src) { return this.ready.get(src) || null; }

  async _page() {
    if (this.page) return this.page;
    if (this.browserFailed) return null;
    const executablePath = findChrome();
    if (!executablePath) { this.browserFailed = true; return null; }
    try {
      const puppeteer = require('puppeteer-core');
      this.browser = await puppeteer.launch({ executablePath, headless: true, args: CHROME_ARGS });
      this.page = await this.browser.newPage();
      return this.page;
    } catch (err) {
      console.warn('DOCX export: Chromium unavailable for image conversion:', err.message);
      this.browserFailed = true;
      return null;
    }
  }

  // Redraws an image (any format the browser decodes) to PNG/JPEG, capped to
  // MAX_PIXELS on the longer side.
  async _raster(src, { jpeg = false, maxPx = MAX_PIXELS } = {}) {
    const page = await this._page();
    if (!page) return null;
    try {
      const out = await page.evaluate(async (s, asJpeg, max) => {
        const img = new Image();
        img.src = s;
        await img.decode();
        let w = img.naturalWidth || 1000, h = img.naturalHeight || 1000;
        const k = Math.min(1, max / Math.max(w, h));
        w = Math.max(1, Math.round(w * k)); h = Math.max(1, Math.round(h * k));
        const c = document.createElement('canvas');
        c.width = w; c.height = h;
        const ctx = c.getContext('2d');
        if (asJpeg) { ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h); }
        ctx.drawImage(img, 0, 0, w, h);
        return { url: c.toDataURL(asJpeg ? 'image/jpeg' : 'image/png', 0.9), w, h };
      }, src, jpeg, maxPx);
      const data = Buffer.from(out.url.split(',')[1], 'base64');
      return { data, type: jpeg ? 'jpg' : 'png', width: out.w, height: out.h };
    } catch (err) {
      console.warn('DOCX export: could not convert an image:', err.message);
      return null;
    }
  }

  async _resolve(src) {
    const parsed = parseDataUrl(src);
    if (!parsed) return null;
    const info = sniff(parsed.buf);
    if (info && NATIVE.has(info.type) && info.width > 0 && info.height > 0) {
      if (Math.max(info.width, info.height) <= MAX_PIXELS) return { data: parsed.buf, ...info };
      // Oversized: downscale when we can, otherwise embed as-is (it is only
      // displayed at page width anyway).
      const small = await this._raster(src, { jpeg: info.type === 'jpg' });
      return small || { data: parsed.buf, ...info };
    }
    return this._raster(src);
  }

  // Decode/convert everything add()ed so far. Never throws.
  async prepare() {
    const list = [...this.pending];
    this.pending.clear();
    for (const src of list) {
      try { this.ready.set(src, await this._resolve(src)); }
      catch { this.ready.set(src, null); }
    }
  }

  // SVG watermark plus a PNG fallback for Word versions without SVG support:
  // rasterised by Chromium when available, else a transparent pixel.
  async watermark(text) {
    const svg = watermarkSvg(text);
    let png = null;
    const r = await this._raster(`data:image/svg+xml;base64,${svg.toString('base64')}`, { maxPx: 1000 });
    if (r) png = r.data;
    return { svg, png: png || transparentPng(), rasterised: !!png };
  }

  async close() {
    if (this.browser) await this.browser.close().catch(() => {});
    this.browser = null; this.page = null;
  }
}

// Scale (w,h) px to fit maxW × maxH px, keeping the ratio.
function fitBox(w, h, maxW, maxH = Infinity) {
  if (!w || !h) return { width: Math.round(maxW), height: Math.round(maxW * 0.6) };
  const k = Math.min(1, maxW / w, maxH / h);
  return { width: Math.max(1, Math.round(w * k)), height: Math.max(1, Math.round(h * k)) };
}

module.exports = { ImageStore, sniff, parseDataUrl, watermarkSvg, transparentPng, fitBox };
