// HTML / Markdown → docx blocks.
//
// The report's rich text arrives as HTML from the browser editor (sections,
// subsections, rewritten finding fields) or as the app's small Markdown
// dialect (finding description/remediation stored in the DB, Free Edit). Both
// end up as Paragraph/Table objects that use the named styles from styles.js,
// so the reader restyles them in Word instead of fighting direct formatting.
//
// The walker keeps inline content in a pending run list and turns it into a
// paragraph whenever a block element starts or ends, which is what makes
// mixed markup (`<div>text<ul>…</ul>more</div>`) come out right. Anything it
// cannot make sense of degrades to plain text instead of throwing.

const {
  Paragraph, TextRun, ImageRun, ExternalHyperlink,
  Table, TableRow, TableCell, WidthType, TableLayoutType, AlignmentType, BorderStyle, ShadingType,
} = require('docx');
const { parse } = require('node-html-parser');
const { fitBox } = require('./images');
const { HEAD_FILL, RULE } = require('./styles');

const PX = 15;   // twips per CSS px at 96 dpi
const MAX_CODE_CHARS = 60000;

const BLOCK_TAGS = new Set([
  'p', 'div', 'section', 'article', 'header', 'footer', 'main', 'aside', 'nav',
  'figure', 'figcaption', 'center', 'address', 'dl', 'dt', 'dd', 'details', 'summary',
  'form', 'fieldset', 'legend', 'body', 'html',
]);
const SKIP_TAGS = new Set(['script', 'style', 'noscript', 'template', 'head', 'title', 'meta', 'link', 'iframe', 'object', 'embed', 'svg', 'canvas', 'video', 'audio', 'input', 'button', 'select', 'textarea', 'colgroup', 'col']);
const HEADINGS = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']);

const DEFAULT_HEADING_MAP = { h1: 'Heading3', h2: 'Heading3', h3: 'Heading3', h4: 'Heading4', h5: 'Heading4', h6: 'Heading4' };

const ALIGN = {
  left: AlignmentType.LEFT, start: AlignmentType.LEFT,
  center: AlignmentType.CENTER,
  right: AlignmentType.RIGHT, end: AlignmentType.RIGHT,
  justify: AlignmentType.JUSTIFIED,
};

const escHtml = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function styleProp(node, prop) {
  const st = node?.getAttribute?.('style');
  if (!st) return null;
  const m = new RegExp(`(?:^|;)\\s*${prop}\\s*:\\s*([^;]+)`, 'i').exec(st);
  return m ? m[1].trim().toLowerCase() : null;
}

function alignOf(node) {
  const a = (styleProp(node, 'text-align') || node?.getAttribute?.('align') || '').toLowerCase();
  return ALIGN[a] ? a : null;
}

function colorOf(node) {
  const c = styleProp(node, 'color') || node?.getAttribute?.('color');
  if (!c) return null;
  let m = /^#([0-9a-f]{6})$/i.exec(c);
  if (m) return m[1].toUpperCase();
  m = /^#([0-9a-f])([0-9a-f])([0-9a-f])$/i.exec(c);
  if (m) return (m[1] + m[1] + m[2] + m[2] + m[3] + m[3]).toUpperCase();
  m = /^rgba?\((\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i.exec(c);
  if (m) return [m[1], m[2], m[3]].map(v => Math.min(255, +v).toString(16).padStart(2, '0')).join('').toUpperCase();
  return null;
}

function decodeEntities(s) {
  // node-html-parser's .text already decodes; this covers rawText leftovers.
  return s.replace(/&nbsp;/g, ' ');
}

function textRun(text, fmt = {}) {
  return new TextRun({
    text,
    bold:        fmt.bold || undefined,
    italics:     fmt.italics || undefined,
    underline:   fmt.underline ? {} : undefined,
    strike:      fmt.strike || undefined,
    superScript: fmt.sup || undefined,
    subScript:   fmt.sub || undefined,
    color:       fmt.color || undefined,
    style:       fmt.code ? 'CodigoCar' : fmt.link ? 'Hyperlink' : undefined,
  });
}

// docx always writes explicit <w:tblBorders> (single/auto on every side when
// none are given), which would override the named table style. Tables that
// should take their borders from the style get that element removed.
function useStyleBorders(table) {
  const props = (table.root || []).find(c => c && c.rootKey === 'w:tblPr');
  if (props && Array.isArray(props.root)) props.root = props.root.filter(c => c && c.rootKey !== 'w:tblBorders');
  return table;
}

// ── Builder ─────────────────────────────────────────────────────────
class Builder {
  // ctx: { images, width (twips), counters: { ol }, headingMap }
  constructor(ctx, out) {
    this.ctx  = ctx;
    this.out  = out;
    this.runs = [];
    this.pp   = null;   // paragraph props of the pending runs
  }

  // ── inline accumulation
  pushRun(r, pp) {
    if (!this.runs.length) this.pp = pp;
    this.runs.push(r);
  }

  flush() {
    const runs = this.runs;
    this.runs = [];
    if (!runs.length) return;
    // Trim collapsible whitespace at both ends.
    const texts = runs.filter(r => r.kind === 'text');
    if (texts.length) {
      texts[0].text = texts[0].text.replace(/^[ \t\n\r]+/, '');
      const last = texts[texts.length - 1];
      last.text = last.text.replace(/[ \t\n\r]+$/, '');
    }
    const meaningful = runs.some(r => (r.kind === 'text' && r.text) || r.kind === 'img' || r.kind === 'link');
    if (!meaningful) return;
    // Trailing <br> adds nothing but an empty line.
    while (runs.length && runs[runs.length - 1].kind === 'br') runs.pop();
    this.out.push(this.paragraph(this.pp, runs.map(r => this.toDocx(r)).filter(Boolean)));
  }

  paragraph(pp, children) {
    const opts = { style: pp.style || 'Normal', children };
    if (pp.align && ALIGN[pp.align]) opts.alignment = ALIGN[pp.align];
    if (pp.list) {
      if (!pp.list.used) { opts.numbering = pp.list.numbering; pp.list.used = true; }
      else opts.indent = { left: 360 + pp.list.level * 340 };
    }
    return new Paragraph(opts);
  }

  toDocx(r) {
    if (r.kind === 'text') return r.text ? textRun(r.text, r.fmt) : null;
    if (r.kind === 'br') return new TextRun({ break: 1 });
    if (r.kind === 'img') return this.imageRun(r.src, r.maxPx);
    if (r.kind === 'link') {
      const kids = r.runs.map(x => this.toDocx(x)).filter(Boolean);
      if (!kids.length) return null;
      return new ExternalHyperlink({ link: r.href, children: kids });
    }
    return null;
  }

  imageRun(src, maxPx) {
    const img = this.ctx.images?.get(src);
    if (!img) return new TextRun({ text: '[imagen no disponible]', italics: true, color: '9CA3AF' });
    const box = fitBox(img.width, img.height, maxPx || this.maxImagePx(), 900);
    return new ImageRun({ type: img.type, data: img.data, transformation: box });
  }

  maxImagePx() { return Math.max(40, Math.floor((this.ctx.width || 9072) / PX) - 4); }

  // ── tree walk
  walkChildren(node, fmt, pp) {
    for (const child of node.childNodes || []) this.walk(child, fmt, pp);
  }

  walk(node, fmt, pp) {
    if (node.nodeType === 3) {
      const raw = decodeEntities(node.text || '');
      const text = fmt.pre ? raw : raw.replace(/[ \t\n\r\f]+/g, ' ');
      if (text) {
        if (fmt.link) this.linkRuns.push({ kind: 'text', text, fmt });
        else this.pushRun({ kind: 'text', text, fmt }, pp);
      }
      return;
    }
    if (node.nodeType !== 1) return;
    const tag = (node.rawTagName || node.tagName || '').toLowerCase();
    if (SKIP_TAGS.has(tag)) return;

    const ownAlign = alignOf(node);
    const bpp = ownAlign ? { ...pp, align: ownAlign } : pp;

    // Inline formatting
    switch (tag) {
      case 'strong': case 'b':
        return this.walkChildren(node, { ...fmt, bold: true }, pp);
      case 'em': case 'i': case 'cite': case 'dfn': case 'var':
        return this.walkChildren(node, { ...fmt, italics: true }, pp);
      case 'u': case 'ins':
        return this.walkChildren(node, { ...fmt, underline: true }, pp);
      case 's': case 'strike': case 'del':
        return this.walkChildren(node, { ...fmt, strike: true }, pp);
      case 'sup':
        return this.walkChildren(node, { ...fmt, sup: true, sub: false }, pp);
      case 'sub':
        return this.walkChildren(node, { ...fmt, sub: true, sup: false }, pp);
      case 'code': case 'kbd': case 'samp': case 'tt':
        return this.walkChildren(node, { ...fmt, code: true }, pp);
      case 'span': case 'font': case 'mark': case 'small': case 'big': case 'abbr': case 'label': case 'q': case 'time': {
        const color = colorOf(node);
        const f = { ...fmt };
        if (color) f.color = color;
        const fw = styleProp(node, 'font-weight');
        if (fw === 'bold' || +fw >= 600) f.bold = true;
        if (styleProp(node, 'font-style') === 'italic') f.italics = true;
        const td = styleProp(node, 'text-decoration') || styleProp(node, 'text-decoration-line') || '';
        if (td.includes('underline')) f.underline = true;
        if (td.includes('line-through')) f.strike = true;
        return this.walkChildren(node, f, pp);
      }
      case 'br':
        if (fmt.link) this.linkRuns.push({ kind: 'br' });
        else this.pushRun({ kind: 'br' }, pp);
        return;
      case 'a': {
        const href = String(node.getAttribute('href') || '').trim();
        if (fmt.link || !/^(https?:|mailto:)/i.test(href)) return this.walkChildren(node, fmt, pp);
        const saved = this.linkRuns;
        this.linkRuns = [];
        this.walkChildren(node, { ...fmt, link: true }, pp);
        const runs = this.linkRuns;
        this.linkRuns = saved;
        if (runs.length) this.pushRun({ kind: 'link', href, runs }, pp);
        return;
      }
      case 'img': {
        const src = node.getAttribute('src') || '';
        if (!src.startsWith('data:')) return;   // remote images are never fetched
        const maxPx = this.imageWidthPx(node);
        const float = styleProp(node, 'float');
        const display = styleProp(node, 'display');
        if (float === 'left' || float === 'right' || display === 'block') {
          this.flush();
          const align = float || (/auto/.test(styleProp(node, 'margin') || '') ? 'center' : pp.align);
          this.out.push(this.paragraph({ style: 'Imagen', align }, [this.imageRun(src, maxPx)]));
          return;
        }
        this.pushRun({ kind: 'img', src, maxPx }, pp);
        return;
      }
    }

    if (HEADINGS.has(tag)) {
      this.flush();
      const style = (this.ctx.headingMap || DEFAULT_HEADING_MAP)[tag] || 'Heading4';
      this.walkChildren(node, fmt, { style, align: ownAlign, list: null });
      this.flush();
      return;
    }
    if (tag === 'ul' || tag === 'ol' || tag === 'menu') {
      this.flush();
      this.list(node, tag === 'ol', fmt, pp);
      return;
    }
    if (tag === 'li') {   // stray <li> with no list around it
      this.flush();
      const level = pp.list ? Math.min(pp.list.level + 1, 5) : 0;
      this.walkChildren(node, fmt, { ...bpp, style: 'ListBullet', list: { numbering: { reference: 'bullets', level }, used: false, level } });
      this.flush();
      return;
    }
    if (tag === 'table') {
      this.flush();
      const t = this.table(node);
      if (t) this.out.push(t);
      return;
    }
    if (tag === 'blockquote') {
      this.flush();
      this.walkChildren(node, fmt, { ...bpp, style: 'Cita', list: null });
      this.flush();
      return;
    }
    if (tag === 'pre') {
      this.flush();
      const block = codeParagraph(preText(node), this.ctx.codeStyle || 'Codigo');
      if (block) this.out.push(block);
      return;
    }
    if (tag === 'hr') {
      this.flush();
      this.out.push(new Paragraph({
        style: 'Normal',
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 1 } },
        spacing: { after: 160 },
        children: [],
      }));
      return;
    }
    if (BLOCK_TAGS.has(tag)) {
      this.flush();
      this.walkChildren(node, fmt, bpp);
      this.flush();
      return;
    }
    // Unknown element: keep its text, inline.
    this.walkChildren(node, fmt, pp);
  }

  imageWidthPx(node) {
    const max = this.maxImagePx();
    const w = styleProp(node, 'width') || node.getAttribute('width') || '';
    let m = /^([\d.]+)%$/.exec(w);
    if (m) return Math.max(24, Math.round(max * Math.min(100, +m[1]) / 100));
    m = /^([\d.]+)(px)?$/.exec(w);
    if (m) return Math.max(16, Math.min(max, Math.round(+m[1])));
    return max;
  }

  list(node, ordered, fmt, pp) {
    const level = pp.list ? Math.min(pp.list.level + 1, 5) : 0;
    const instance = ordered ? ++this.ctx.counters.ol : undefined;
    const numbering = ordered
      ? { reference: 'ordered', level, instance }
      : { reference: 'bullets', level };
    for (const child of node.childNodes || []) {
      if (child.nodeType === 3 && !child.text.trim()) continue;
      const tag = (child.rawTagName || '').toLowerCase();
      if (tag === 'ul' || tag === 'ol') { this.flush(); this.list(child, tag === 'ol', fmt, { ...pp, list: { level, used: true } }); continue; }
      const own = child.nodeType === 1 ? alignOf(child) : null;
      const lpp = {
        style: ordered ? 'ListNumber' : 'ListBullet',
        align: own || pp.align,
        list: { numbering, used: false, level },
      };
      if (tag === 'li') this.walkChildren(child, fmt, lpp);
      else this.walk(child, fmt, lpp);
      this.flush();
    }
  }

  table(node) {
    const rows = [];
    const collect = n => {
      for (const c of n.childNodes || []) {
        const t = (c.rawTagName || '').toLowerCase();
        if (t === 'tr') rows.push({ tr: c, head: n !== node && (n.rawTagName || '').toLowerCase() === 'thead' });
        else if (t === 'thead' || t === 'tbody' || t === 'tfoot') collect(c);
      }
    };
    collect(node);
    if (!rows.length) return null;

    const grid = rows.map(({ tr, head }) => {
      const cells = (tr.childNodes || []).filter(c => ['td', 'th'].includes((c.rawTagName || '').toLowerCase()));
      return { head, cells: cells.map(c => ({ node: c, th: c.rawTagName.toLowerCase() === 'th', span: Math.max(1, Math.min(20, parseInt(c.getAttribute('colspan'), 10) || 1)) })) };
    }).filter(r => r.cells.length);
    if (!grid.length) return null;

    const nCols = Math.max(...grid.map(r => r.cells.reduce((a, c) => a + c.span, 0)));
    const width = this.ctx.width || 9072;
    const colW  = Math.floor(width / nCols);

    const tRows = grid.map(r => {
      const isHead = r.head || r.cells.every(c => c.th);
      let used = 0;
      const cells = r.cells.map(c => {
        used += c.span;
        const cw = colW * c.span;
        const blocks = htmlNodeToBlocks(c.node, {
          ...this.ctx, width: Math.max(600, cw - 240),
        }, { style: c.th ? 'TablaCabecera' : 'TablaTexto', align: alignOf(c.node) });
        return new TableCell({
          columnSpan: c.span > 1 ? c.span : undefined,
          width: { size: cw, type: WidthType.DXA },
          shading: c.th ? { type: ShadingType.CLEAR, fill: HEAD_FILL, color: 'auto' } : undefined,
          children: blocks.length ? blocks : [new Paragraph({ style: c.th ? 'TablaCabecera' : 'TablaTexto', children: [] })],
        });
      });
      // Pad short rows so Word does not draw a ragged edge.
      for (; used < nCols; used++) {
        cells.push(new TableCell({ width: { size: colW, type: WidthType.DXA }, children: [new Paragraph({ style: 'TablaTexto', children: [] })] }));
      }
      return new TableRow({ tableHeader: isHead || undefined, children: cells });
    });

    return useStyleBorders(new Table({
      style: 'TablaResility',
      width: { size: colW * nCols, type: WidthType.DXA },
      columnWidths: Array(nCols).fill(colW),
      layout: TableLayoutType.FIXED,
      rows: tRows,
    }));
  }
}

function preText(node) {
  let s = '';
  const rec = n => {
    for (const c of n.childNodes || []) {
      if (c.nodeType === 3) s += decodeEntities(c.text);
      else if ((c.rawTagName || '').toLowerCase() === 'br') s += '\n';
      else if (c.nodeType === 1) {
        const t = (c.rawTagName || '').toLowerCase();
        rec(c);
        if (t === 'div' || t === 'p') s += '\n';
      }
    }
  };
  rec(node);
  return s.replace(/\n+$/, '');
}

// One paragraph per code block, lines separated by breaks, in the "Código"
// style. numbered → each line gets a grey line number (HTTP proofs).
function codeParagraph(text, style = 'Codigo', { numbered = false } = {}) {
  if (text == null) return null;
  let src = String(text).replace(/\r\n?/g, '\n').replace(/\n+$/, '');
  if (!src.trim()) return null;
  if (src.length > MAX_CODE_CHARS) src = src.slice(0, MAX_CODE_CHARS) + '\n…';
  const lines = src.split('\n');
  const pad = String(lines.length).length;
  const children = [];
  lines.forEach((line, i) => {
    if (numbered) {
      children.push(new TextRun({ text: `${String(i + 1).padStart(pad, ' ')}  `, style: 'NumeroLinea', break: i ? 1 : undefined }));
      if (line) children.push(new TextRun({ text: line }));
    } else {
      children.push(new TextRun({ text: line, break: i ? 1 : undefined }));
    }
  });
  return new Paragraph({ style, children });
}

function plainText(html) {
  return String(html || '').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li|h\d|tr)>/gi, '\n').replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim();
}

function fallbackBlocks(html, base) {
  const text = plainText(html);
  if (!text) return [];
  return text.split('\n').map(line => new Paragraph({ style: base.style || 'Normal', children: [new TextRun(line)] }));
}

function htmlNodeToBlocks(node, ctx, base = {}) {
  const out = [];
  const b = new Builder(ctx, out);
  b.walkChildren(node, {}, { style: base.style || 'Normal', align: base.align || null, list: null });
  b.flush();
  return out;
}

// ctx: { images, width, counters: { ol }, headingMap?, codeStyle? }
// base: { style, align } for the paragraphs it produces.
function htmlToBlocks(html, ctx, base = {}) {
  if (typeof html !== 'string' || !html.trim()) return [];
  try {
    const root = parse(`<div>${html}</div>`, {
      lowerCaseTagName: true, comment: false,
      blockTextElements: { script: true, style: true, noscript: true },
    });
    // The whole root, not just the wrapper: with broken markup the parser can
    // close the wrapper early and leave the rest of the content as siblings.
    return htmlNodeToBlocks(root, ctx, base);
  } catch {
    return fallbackBlocks(html, base);
  }
}

// ── Markdown ────────────────────────────────────────────────────────
function mdInline(text) {
  const parts = [];
  const re = /`([^`]+)`/g;
  let last = 0, m;
  const apply = t => escHtml(t)
    .replace(/\*\*([^*<>]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*<>]+)\*/g, '<em>$1</em>');
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(apply(text.slice(last, m.index)));
    parts.push(`<code>${escHtml(m[1])}</code>`);
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(apply(text.slice(last)));
  return parts.join('');
}

// Port of the frontend's renderMd() (js/services/utils.js) — the dialect the
// finding description/remediation/notes are stored in — to semantic HTML.
// styled = true follows renderMdStyled() instead (Free Edit): # / ## / ###
// are real headings there.
function mdToHtml(raw, { styled = false } = {}) {
  if (!raw) return '';
  const out = [];
  let inCode = false, code = [], table = [], list = [], para = [];
  const flushPara  = () => { if (para.length) { out.push(`<p>${para.map(mdInline).join('<br>')}</p>`); para = []; } };
  const flushList  = () => { if (list.length) { out.push(`<ul>${list.map(i => `<li>${mdInline(i)}</li>`).join('')}</ul>`); list = []; } };
  const flushTable = () => {
    if (!table.length) return;
    const [head, , ...body] = table;
    const cols = head.split('|').slice(1, -1).map(c => c.trim());
    out.push(`<table><thead><tr>${cols.map(c => `<th>${mdInline(c)}</th>`).join('')}</tr></thead><tbody>${
      body.map(row => {
        const cells = row.split('|').slice(1, -1).map(c => c.trim());
        return `<tr>${cols.map((_, i) => `<td>${mdInline(cells[i] || '')}</td>`).join('')}</tr>`;
      }).join('')}</tbody></table>`);
    table = [];
  };
  const flushAll = () => { flushPara(); flushList(); flushTable(); };
  for (const line of String(raw).replace(/\r\n?/g, '\n').split('\n')) {
    if (!inCode && line.startsWith('```')) { flushAll(); inCode = true; code = []; continue; }
    if (inCode) {
      if (line.startsWith('```')) { inCode = false; out.push(`<pre><code>${escHtml(code.join('\n'))}</code></pre>`); }
      else code.push(line);
      continue;
    }
    if (/^\|.+\|/.test(line)) { flushPara(); flushList(); table.push(line); continue; }
    flushTable();
    const h = /^(#{1,4}) (.*)$/.exec(line);
    if (h) {
      flushAll();
      if (styled) { const lvl = h[1].length; out.push(`<h${lvl}>${mdInline(h[2])}</h${lvl}>`); }
      else out.push(`<p><strong>${mdInline(h[2])}</strong></p>`);
      continue;
    }
    if (/^[-*] /.test(line)) { flushPara(); list.push(line.slice(2)); continue; }
    flushList();
    if (line.trim() === '') { flushPara(); continue; }
    para.push(line);
  }
  if (inCode) out.push(`<pre><code>${escHtml(code.join('\n'))}</code></pre>`);
  flushAll();
  return out.join('');
}

// Rich editor fields are HTML; legacy ones are Markdown (same test as the
// frontend's _secContentHtml).
function contentToHtml(content) {
  if (!content) return '';
  return /<[a-zA-Z][\s\S]*?>/.test(content) ? content : mdToHtml(content);
}

module.exports = { useStyleBorders, htmlToBlocks, mdToHtml, contentToHtml, codeParagraph, plainText, escHtml, PX };
