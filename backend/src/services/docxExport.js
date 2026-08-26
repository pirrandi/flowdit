const {
  Document, Packer, Paragraph, TextRun,
  Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, WidthType,
  BorderStyle, ShadingType, PageBreak,
  VerticalAlign, convertInchesToTwip,
} = require('docx');
const { parse: parseHtml } = require('node-html-parser');

// ── WSTG test ID → name ──────────────────────────────────────────────
const WSTG_NAMES = {
  'WSTG-INFO-01':'Search Engine Discovery & Recon',
  'WSTG-INFO-02':'Fingerprint Web Server',
  'WSTG-INFO-03':'Review Webserver Metafiles for Information Leakage',
  'WSTG-INFO-04':'Enumerate Applications on Webserver',
  'WSTG-INFO-05':'Review Webpage Content for Information Leakage',
  'WSTG-INFO-06':'Identify Application Entry Points',
  'WSTG-INFO-07':'Map Execution Paths Through Application',
  'WSTG-INFO-08':'Fingerprint Web Application Framework',
  'WSTG-INFO-09':'Fingerprint Web Application',
  'WSTG-INFO-10':'Map Application Architecture',
  'WSTG-CONF-01':'Test Network Infrastructure Configuration',
  'WSTG-CONF-02':'Test Application Platform Configuration',
  'WSTG-CONF-03':'Test File Extensions Handling',
  'WSTG-CONF-04':'Review Old Backup and Unreferenced Files',
  'WSTG-CONF-05':'Enumerate Admin Interfaces',
  'WSTG-CONF-06':'Test HTTP Methods',
  'WSTG-CONF-07':'Test HTTP Strict Transport Security (HSTS)',
  'WSTG-CONF-08':'Test RIA Cross Domain Policy',
  'WSTG-CONF-10':'Test for Subdomain Takeover',
  'WSTG-CONF-11':'Test Cloud Storage',
  'WSTG-CONF-12':'Testing for Content Security Policy (CSP)',
  'WSTG-CONF-14':'Test HTTP Security Header Misconfigurations',
  'WSTG-IDNT-01':'Test Role Definitions',
  'WSTG-IDNT-02':'Test User Registration Process',
  'WSTG-IDNT-04':'Testing for Account Enumeration',
  'WSTG-IDNT-05':'Testing for Weak Username Policy',
  'WSTG-ATHN-01':'Testing for Credentials over Encrypted Channel',
  'WSTG-ATHN-02':'Testing for Default Credentials',
  'WSTG-ATHN-03':'Testing for Weak Lock Out Mechanism',
  'WSTG-ATHN-04':'Testing for Bypassing Authentication Schema',
  'WSTG-ATHN-07':'Testing for Weak Password Policy',
  'WSTG-ATHN-09':'Testing for Weak Password Change or Reset',
  'WSTG-ATHN-11':'Testing Multi-Factor Authentication (MFA)',
  'WSTG-ATHZ-01':'Testing Directory Traversal / File Include',
  'WSTG-ATHZ-02':'Testing for Bypassing Authorization Schema',
  'WSTG-ATHZ-04':'Testing for Insecure Direct Object References (IDOR)',
  'WSTG-ATHZ-05':'Testing for OAuth Weaknesses',
  'WSTG-SESS-01':'Testing for Session Management Schema',
  'WSTG-SESS-02':'Testing for Cookie Attributes',
  'WSTG-SESS-05':'Testing for Cross Site Request Forgery (CSRF)',
  'WSTG-SESS-10':'Testing JSON Web Tokens (JWT)',
  'WSTG-INPV-01':'Testing for Reflected XSS',
  'WSTG-INPV-02':'Testing for Stored XSS',
  'WSTG-INPV-05':'Testing for SQL Injection',
  'WSTG-INPV-07':'Testing for XML Injection (XXE)',
  'WSTG-INPV-12':'Testing for Command Injection',
  'WSTG-INPV-18':'Testing for Server-Side Template Injection (SSTI)',
  'WSTG-INPV-19':'Testing for Server-Side Request Forgery (SSRF)',
  'WSTG-INPV-20':'Testing for Mass Assignment',
  'WSTG-CLNT-01':'Testing for DOM-Based XSS',
  'WSTG-CLNT-04':'Testing for Client-Side URL Redirect',
  'WSTG-CLNT-07':'Test Cross Origin Resource Sharing (CORS)',
  'WSTG-CLNT-09':'Testing for Clickjacking',
  'WSTG-CLNT-10':'Testing WebSockets',
  'WSTG-CLNT-12':'Test Browser Storage',
  'WSTG-APIT-01':'API Reconnaissance',
  'WSTG-APIT-02':'API Broken Object Level Authorization (BOLA)',
  'WSTG-APIT-99':'Testing GraphQL',
};

// ── Palette ──────────────────────────────────────────────────────────
const SEV = {
  critical: { fill: 'FEF2F2', text: 'B91C1C', label: 'CRITICAL' },
  high:     { fill: 'FFF7ED', text: 'C2410C', label: 'HIGH'     },
  medium:   { fill: 'FEFCE8', text: '92400E', label: 'MEDIUM'   },
  low:      { fill: 'F0FDF4', text: '15803D', label: 'LOW'      },
  info:     { fill: 'F9FAFB', text: '374151', label: 'INFO'     },
};
const ACCENT    = '5B21B6';
const GRAY_FILL = 'F3F4F6';
const GRAY_BRD  = 'D1D5DB';
const TEXT_MAIN = '111827';
const TEXT_MUTE = '6B7280';

const BORDER_LIGHT = { style: BorderStyle.SINGLE, size: 1, color: GRAY_BRD };
const BORDER_NONE  = { style: BorderStyle.NIL,    size: 0, color: 'auto'   };
const CELL_MARGIN  = { top: 80, bottom: 80, left: 120, right: 120 };

// ── HTML → DOCX converter ────────────────────────────────────────────

function walkInline(node, fmt = {}) {
  const runs = [];
  for (const child of node.childNodes) {
    if (child.nodeType === 3) {
      const text = child.text;
      if (text) runs.push(new TextRun({
        text,
        bold:    fmt.bold    || false,
        italics: fmt.italic  || false,
        font:    fmt.code ? 'Consolas' : 'Calibri',
        size:    fmt.code ? 20 : 22,
        color:   fmt.code ? '374151' : (fmt.color || TEXT_MAIN),
        shading: fmt.code ? { type: ShadingType.CLEAR, fill: 'F4F4F5', color: 'auto' } : undefined,
      }));
      continue;
    }
    const tag = child.tagName?.toLowerCase();
    if (!tag) { runs.push(...walkInline(child, fmt)); continue; }
    if (tag === 'strong' || tag === 'b')  { runs.push(...walkInline(child, { ...fmt, bold: true }));   continue; }
    if (tag === 'em'     || tag === 'i')  { runs.push(...walkInline(child, { ...fmt, italic: true })); continue; }
    if (tag === 'code')                   { runs.push(...walkInline(child, { ...fmt, code: true }));   continue; }
    if (tag === 'br')                     { runs.push(new TextRun({ break: 1 }));                      continue; }
    // for <a>, <span>, etc. just recurse
    runs.push(...walkInline(child, fmt));
  }
  return runs;
}

function walkBlock(node) {
  const out = [];
  for (const child of node.childNodes) {
    if (child.nodeType === 3) {
      const text = child.text.trim();
      if (text) out.push(new Paragraph({ children: [new TextRun({ text, font: 'Calibri', size: 22, color: TEXT_MAIN })] }));
      continue;
    }
    const tag = child.tagName?.toLowerCase();
    if (!tag) continue;

    switch (tag) {
      case 'h1':
        out.push(new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 80 }, children: walkInline(child, { bold: true }) }));
        break;
      case 'h2':
        out.push(new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 80 }, children: walkInline(child, { bold: true }) }));
        break;
      case 'h3': case 'h4':
        out.push(new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 160, after: 60 }, children: walkInline(child, { bold: true }) }));
        break;
      case 'pre': {
        const lines = child.text.split('\n');
        lines.forEach((line, i) => out.push(new Paragraph({
          spacing: { before: i === 0 ? 80 : 0, after: i === lines.length - 1 ? 80 : 0 },
          shading: { type: ShadingType.CLEAR, fill: 'F4F4F5', color: 'auto' },
          children: [new TextRun({ text: line, font: 'Consolas', size: 20, color: '374151' })],
        })));
        break;
      }
      case 'ul': {
        for (const li of child.querySelectorAll(':scope > li')) {
          out.push(new Paragraph({
            indent: { left: convertInchesToTwip(0.3) },
            spacing: { after: 40 },
            children: [
              new TextRun({ text: '• ', font: 'Calibri', size: 22, bold: true, color: ACCENT }),
              ...walkInline(li),
            ],
          }));
          // nested lists inside li
          const nested = li.querySelectorAll(':scope > ul, :scope > ol');
          nested.forEach(n => out.push(...walkBlock(n)));
        }
        break;
      }
      case 'ol': {
        let idx = 1;
        for (const li of child.querySelectorAll(':scope > li')) {
          out.push(new Paragraph({
            indent: { left: convertInchesToTwip(0.3) },
            spacing: { after: 40 },
            children: [
              new TextRun({ text: `${idx++}. `, font: 'Calibri', size: 22, bold: true, color: TEXT_MUTE }),
              ...walkInline(li),
            ],
          }));
        }
        break;
      }
      case 'table': {
        const tblNode = walkHtmlTable(child);
        if (tblNode) out.push(tblNode);
        break;
      }
      case 'hr':
        out.push(new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: GRAY_BRD } },
          spacing: { after: 120 },
          children: [],
        }));
        break;
      case 'p': case 'div': case 'section': case 'article': {
        const runs = walkInline(child);
        if (runs.length) {
          out.push(new Paragraph({ spacing: { after: 80 }, children: runs }));
        } else {
          // div with nested blocks
          const nested = walkBlock(child);
          out.push(...nested);
        }
        break;
      }
      case 'blockquote': {
        const runs = walkInline(child);
        out.push(new Paragraph({
          indent: { left: convertInchesToTwip(0.3) },
          border: { left: { style: BorderStyle.SINGLE, size: 6, color: ACCENT } },
          spacing: { after: 80 },
          children: runs.map(r => Object.assign(Object.create(Object.getPrototypeOf(r)), r, { italics: true })),
        }));
        break;
      }
      default: {
        const runs = walkInline(child);
        if (runs.length) out.push(new Paragraph({ spacing: { after: 80 }, children: runs }));
        else out.push(...walkBlock(child));
      }
    }
  }
  return out;
}

function walkHtmlTable(node) {
  const rows = [];
  const trNodes = node.querySelectorAll('tr');
  trNodes.forEach((tr, ri) => {
    const cells = [];
    tr.querySelectorAll('td, th').forEach(td => {
      const isHdr = td.tagName === 'TH';
      cells.push(new TableCell({
        children: [new Paragraph({
          children: [new TextRun({
            text: td.text.trim(),
            bold: isHdr,
            font: 'Calibri',
            size: 20,
            color: isHdr ? '374151' : TEXT_MAIN,
          })],
        })],
        margins: CELL_MARGIN,
        shading: isHdr || ri % 2 === 1
          ? { type: ShadingType.CLEAR, fill: isHdr ? GRAY_FILL : 'FAFAFA', color: 'auto' }
          : undefined,
        borders: {
          top:    BORDER_LIGHT,
          bottom: BORDER_LIGHT,
          left:   BORDER_NONE,
          right:  BORDER_NONE,
        },
      }));
    });
    if (cells.length) rows.push(new TableRow({ tableHeader: trNodes[ri]?.querySelectorAll('th').length > 0, children: cells }));
  });
  if (!rows.length) return null;
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: { top: BORDER_LIGHT, bottom: BORDER_LIGHT, left: BORDER_NONE, right: BORDER_NONE, insideH: BORDER_LIGHT, insideV: BORDER_NONE },
    rows,
  });
}

// Converts an HTML string (from the rich editor) to DOCX block elements
function htmlToDocx(html) {
  if (!html?.trim()) return [];
  const root = parseHtml(`<div>${html}</div>`);
  return walkBlock(root.firstChild);
}

// ── Primitive helpers ────────────────────────────────────────────────

function spacer(size = 140) {
  return new Paragraph({ text: '', spacing: { after: size } });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

function p(text, { bold = false, color = TEXT_MAIN, size = 22, italic = false, align, spacing } = {}) {
  return new Paragraph({
    alignment: align,
    spacing,
    children: [new TextRun({ text: String(text ?? ''), bold, color, size, font: 'Calibri', italics: italic })],
  });
}

function sectionH2(title) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 320, after: 120 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: ACCENT } },
    children: [new TextRun({ text: title, bold: true, color: TEXT_MAIN, size: 28, font: 'Calibri' })],
  });
}

function sectionH3(text, sevColor) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 240, after: 80 },
    children: [new TextRun({ text, bold: true, color: sevColor || TEXT_MAIN, size: 24, font: 'Calibri' })],
  });
}

function labelText(text) {
  return new Paragraph({
    spacing: { after: 40 },
    children: [new TextRun({ text: text.toUpperCase(), bold: true, color: TEXT_MUTE, size: 18, font: 'Calibri' })],
  });
}

function codeBlock(text) {
  if (!text?.trim()) return [];
  return text.split('\n').map((line, i, arr) => new Paragraph({
    spacing: { before: i === 0 ? 80 : 0, after: i === arr.length - 1 ? 80 : 0 },
    shading: { type: ShadingType.CLEAR, fill: 'F4F4F5', color: 'auto' },
    children: [new TextRun({ text: line, font: 'Consolas', size: 20, color: '374151' })],
  }));
}

function _fieldBlock(labelStr, value) {
  if (!value?.trim()) return [];
  return [labelText(labelStr), ...htmlToDocx(value), spacer(80)];
}

// Renders sec.description intro + subsections for any section
function renderSectionExtras(sec) {
  const out = [];
  if (sec?.description?.trim()) {
    out.push(...htmlToDocx(sec.description));
    out.push(spacer(80));
  }
  const subs = (sec?.children || []).filter(c => c.visible !== false);
  subs.forEach(sub => {
    out.push(sectionH3(sub.title || 'Subsection'));
    if (sub.content?.trim()) out.push(...htmlToDocx(sub.content));
    out.push(spacer(60));
  });
  return out;
}

// ── Table helpers ────────────────────────────────────────────────────

function tc(content, { width, fill, bold = false, color = TEXT_MAIN, size = 20, align, colspan } = {}) {
  const textContent = typeof content === 'string'
    ? new Paragraph({
        alignment: align,
        children: [new TextRun({ text: content, bold, color, size, font: 'Calibri' })],
      })
    : content;

  return new TableCell({
    children: [textContent],
    margins: CELL_MARGIN,
    verticalAlign: VerticalAlign.CENTER,
    columnSpan: colspan,
    width: width ? { size: width, type: WidthType.PERCENTAGE } : undefined,
    shading: fill ? { type: ShadingType.CLEAR, fill, color: 'auto' } : undefined,
    borders: { top: BORDER_LIGHT, bottom: BORDER_LIGHT, left: BORDER_NONE, right: BORDER_NONE },
  });
}

function headerRow(cells) {
  return new TableRow({
    tableHeader: true,
    children: cells.map(c => tc(c.text, { fill: GRAY_FILL, bold: true, color: '374151', size: 18, width: c.width, align: c.align })),
  });
}

function dataRow(cells, { shaded = false } = {}) {
  const fill = shaded ? 'FAFAFA' : 'FFFFFF';
  return new TableRow({
    children: cells.map(c => {
      if (c.para) return new TableCell({
        children: [c.para],
        margins: CELL_MARGIN,
        verticalAlign: VerticalAlign.TOP,
        width: c.width ? { size: c.width, type: WidthType.PERCENTAGE } : undefined,
        shading: { type: ShadingType.CLEAR, fill, color: 'auto' },
        borders: { top: BORDER_LIGHT, bottom: BORDER_LIGHT, left: BORDER_NONE, right: BORDER_NONE },
      });
      return tc(c.text ?? '', { fill: c.fill || fill, color: c.color || '374151', size: 20, width: c.width, bold: c.bold, align: c.align });
    }),
  });
}

function tbl(rows) {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: { top: BORDER_LIGHT, bottom: BORDER_LIGHT, left: BORDER_NONE, right: BORDER_NONE, insideH: BORDER_LIGHT, insideV: BORDER_NONE },
    rows,
  });
}

function sevRuns(sev) {
  const s = SEV[sev] || SEV.info;
  return [
    new TextRun({ text: ' ', size: 20 }),
    new TextRun({ text: s.label, bold: true, color: s.text, size: 18, font: 'Calibri',
      shading: { type: ShadingType.CLEAR, fill: s.fill, color: 'auto' } }),
    new TextRun({ text: ' ', size: 20 }),
  ];
}

// ── Misc helpers ─────────────────────────────────────────────────────

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function getSectionObj(sections, id) {
  return sections?.find(s => s.id === id || s.type === id);
}

function _isSectionVisible(id, sections) {
  if (!sections?.length) return true;
  const sec = getSectionObj(sections, id);
  return !sec || sec.visible !== false;
}

function countBySev(vulns) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulns.forEach(v => { if (c[v.severity] !== undefined) c[v.severity]++; });
  return c;
}

// ── Section builders ─────────────────────────────────────────────────

function buildCover(project, vulns, meta, type) {
  const counts = countBySev(vulns);
  const total  = vulns.length;

  return [
    new Paragraph({
      spacing: { after: 320 },
      border: { top: { style: BorderStyle.SINGLE, size: 24, color: ACCENT } },
      children: [],
    }),
    p(`PENETRATION TEST REPORT — ${type === 'executive' ? 'EXECUTIVE SUMMARY' : 'TECHNICAL REPORT'}`, {
      color: ACCENT, size: 18, bold: true,
    }),
    spacer(80),
    new Paragraph({
      spacing: { after: 80 },
      children: [new TextRun({ text: meta.coverTitle || project.name, bold: true, color: TEXT_MAIN, size: 52, font: 'Calibri' })],
    }),
    meta.organization
      ? p(`Client: ${meta.organization}`, { color: TEXT_MUTE, size: 24, italic: true })
      : spacer(40),
    spacer(240),
    tbl([
      headerRow([{ text: 'Field', width: 30 }, { text: 'Value', width: 70 }]),
      ...[
        ['Date',           formatDate(meta.coverDate || project.date_report || new Date())],
        ['Target',         project.target || '—'],
        ['Prepared By',    meta.preparedBy || '—'],
        ['Organization',   meta.organization || '—'],
        ['Classification', meta.classification || 'Confidential'],
        ['Total Findings', String(total)],
      ].map(([f, v], i) => dataRow([{ text: f, width: 30, bold: true }, { text: v, width: 70 }], { shaded: i % 2 === 1 })),
    ]),
    spacer(200),
    tbl([
      headerRow(['critical','high','medium','low','info'].map(s => ({ text: SEV[s].label, width: 20, align: AlignmentType.CENTER }))),
      dataRow(['critical','high','medium','low','info'].map(s => ({
        text:  String(counts[s]),
        width: 20,
        align: AlignmentType.CENTER,
        color: counts[s] > 0 ? SEV[s].text : TEXT_MUTE,
        bold:  counts[s] > 0,
        fill:  counts[s] > 0 ? SEV[s].fill : 'FFFFFF',
      }))),
    ]),
    spacer(320),
    pageBreak(),
  ];
}

function buildExecSummary(vulns, sec) {
  const counts = countBySev(vulns);
  const total  = vulns.length;
  const title  = sec?.title || 'Executive Summary';
  const out    = [sectionH2(title)];

  // Intro text from editor
  out.push(...renderSectionExtras(sec));

  // Auto-generated intro if no custom text and no subsections
  if (!sec?.description?.trim() && !(sec?.children?.filter(c => c.visible !== false).length)) {
    out.push(p(
      `This penetration test identified ${total} finding${total !== 1 ? 's' : ''} across the assessed scope.` +
      (counts.critical > 0 ? ` ${counts.critical} critical issue${counts.critical > 1 ? 's' : ''} require immediate remediation.` : ''),
      { color: '374151', size: 22 }
    ));
    out.push(spacer(120));
  }

  out.push(tbl([
    headerRow([
      { text: 'Severity',    width: 20 },
      { text: 'Count',       width: 12, align: AlignmentType.CENTER },
      { text: 'Description', width: 68 },
    ]),
    ...Object.entries({
      critical: 'Exploitable with significant impact; immediate action required.',
      high:     'High likelihood of exploitation; prioritize remediation.',
      medium:   'Moderate risk; schedule remediation in near term.',
      low:      'Low impact; remediate as part of routine maintenance.',
      info:     'Informational findings; consider as hardening recommendations.',
    }).map(([sev, desc], i) => new TableRow({ children: [
      tc(SEV[sev].label, { fill: SEV[sev].fill, color: SEV[sev].text, width: 20, bold: true, size: 20 }),
      tc(String(counts[sev]), { fill: counts[sev] > 0 ? SEV[sev].fill : 'FFFFFF', color: counts[sev] > 0 ? SEV[sev].text : TEXT_MUTE, width: 12, bold: counts[sev] > 0, align: AlignmentType.CENTER }),
      tc(desc, { fill: i % 2 === 1 ? 'FAFAFA' : 'FFFFFF', width: 68, size: 20 }),
    ]})),
  ]));

  out.push(spacer(200), pageBreak());
  return out;
}

function buildFindingsIndex(vulns, sec) {
  if (!vulns.length) return [];
  const title = sec?.title || 'Findings Index';
  const out   = [sectionH2(title)];

  out.push(...renderSectionExtras(sec));

  out.push(tbl([
    headerRow([
      { text: '#',        width: 6  },
      { text: 'Finding',  width: 46 },
      { text: 'Severity', width: 16 },
      { text: 'CVSS',     width: 12 },
      { text: 'Target',   width: 20 },
    ]),
    ...vulns.map((v, i) => {
      const s     = SEV[v.severity] || SEV.info;
      const score = v.cvss_score != null ? String(v.cvss_score) : '—';
      return new TableRow({ children: [
        tc(String(i + 1),        { fill: i%2?'FAFAFA':'FFFFFF', width: 6,  color: TEXT_MUTE }),
        tc(v.name,               { fill: i%2?'FAFAFA':'FFFFFF', width: 46, bold: true }),
        tc(s.label,              { fill: s.fill, color: s.text, width: 16, bold: true }),
        tc(score,                { fill: i%2?'FAFAFA':'FFFFFF', width: 12, color: TEXT_MUTE }),
        tc(v.target_host || '—', { fill: i%2?'FAFAFA':'FFFFFF', width: 20 }),
      ]});
    }),
  ]));

  out.push(spacer(200), pageBreak());
  return out;
}

function buildDetailedFindings(vulns, sec) {
  if (!vulns.length) return [];
  const title = sec?.title || 'Detailed Findings';
  const out   = [sectionH2(title)];

  out.push(...renderSectionExtras(sec));

  vulns.forEach((v, i) => {

    out.push(new Paragraph({
      spacing: { before: i === 0 ? 0 : 320, after: 120 },
      heading: HeadingLevel.HEADING_3,
      children: [
        new TextRun({ text: `${i + 1}. ${v.name}`, bold: true, color: TEXT_MAIN, size: 26, font: 'Calibri' }),
        ...sevRuns(v.severity),
      ],
    }));

    const metaParts = [];
    if (v.category)    metaParts.push(`Category: ${v.category}`);
    if (v.cwe)         metaParts.push(`CWE: ${v.cwe}`);
    if (v.cvss_score != null) metaParts.push(`CVSS: ${v.cvss_score}`);
    if (v.cvss_vector) metaParts.push(v.cvss_vector);
    const complianceTags = Array.isArray(v.compliance_tags) ? v.compliance_tags : [];
    if (complianceTags.length) metaParts.push(`PCI-DSS: ${complianceTags.map(t => t.control_id).join(', ')}`);
    if (metaParts.length) out.push(p(metaParts.join('  ·  '), { color: TEXT_MUTE, size: 19, italic: true }));
    out.push(spacer(80));

    // Description (HTML from DB)
    if (v.description?.trim()) {
      out.push(labelText('Description'));
      out.push(...htmlToDocx(v.description));
      out.push(spacer(80));
    }

    // Remediation
    if (v.remediation?.trim()) {
      out.push(labelText('Remediation'));
      out.push(...htmlToDocx(v.remediation));
      out.push(spacer(80));
    }

    // PCI-DSS compliance coverage
    if (complianceTags.length) {
      out.push(labelText('PCI-DSS Coverage'));
      complianceTags.forEach(t => {
        out.push(new Paragraph({
          spacing: { after: 40 },
          children: [
            new TextRun({ text: `${t.control_id}  `, bold: true, color: ACCENT, size: 20, font: 'Calibri' }),
            new TextRun({ text: t.title || '', color: TEXT_MAIN, size: 20, font: 'Calibri' }),
          ],
        }));
      });
      out.push(spacer(80));
    }

    // Payloads
    const payloads = Array.isArray(v.payloads) ? v.payloads : [];
    if (payloads.length) {
      out.push(labelText('Payloads / Proof of Concept'));
      payloads.forEach(pl => {
        const text = typeof pl === 'object' ? JSON.stringify(pl, null, 2) : String(pl);
        out.push(...codeBlock(text));
      });
      out.push(spacer(80));
    }

    // Notes
    if (v.notes?.trim()) {
      out.push(labelText('Notes'));
      out.push(...htmlToDocx(v.notes));
      out.push(spacer(80));
    }

    // Evidence count (screenshots live in PDF)
    const evidence = Array.isArray(v.evidence) ? v.evidence : [];
    if (evidence.length) {
      out.push(p(`Evidence: ${evidence.length} file(s) — see PDF export for screenshots.`, { color: TEXT_MUTE, size: 19, italic: true }));
      out.push(spacer(80));
    }

    // HTTP Proofs (request/response from scanner imports)
    const httpProofs = (Array.isArray(v.http_proofs) ? v.http_proofs : []).filter(p => p.include !== false);
    if (httpProofs.length) {
      out.push(labelText(`HTTP Proofs (${httpProofs.length})`));
      httpProofs.forEach((proof, idx) => {
        const label = proof.method ? `${proof.method} — Proof #${idx + 1}` : `Proof #${idx + 1}`;
        out.push(p(label, { bold: true, size: 20, color: TEXT_MUTE }));
        const addNumbered = (label, text) => {
          out.push(p(label, { size: 18, italic: true, color: TEXT_MUTE }));
          const lines = text.slice(0, 4000).split('\n');
          const pad = String(lines.length).length;
          out.push(...codeBlock(lines.map((l, i) => `${String(i+1).padStart(pad,' ')}  ${l}`).join('\n')));
        };
        if (proof.request?.trim())  addNumbered('Request',  proof.request);
        if (proof.response?.trim()) addNumbered('Response', proof.response);
        if (proof.annotation?.trim()) {
          out.push(new Paragraph({
            spacing: { before: 80, after: 0 },
            border: { left: { style: BorderStyle.SINGLE, size: 6, color: 'F59E0B' } },
            indent: { left: 160 },
            children: [new TextRun({ text: 'Anotación: ', bold: true, size: 20, color: '92400E' }),
                       new TextRun({ text: proof.annotation.replace(/`([^`]+)`/g, '$1'), size: 20, color: '92400E' })],
          }));
        }
        out.push(spacer(80));
      });
    }

    out.push(new Paragraph({ spacing: { after: 0 }, border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: 'E5E7EB' } }, children: [] }));
  });

  out.push(spacer(200), pageBreak());
  return out;
}

function buildWstg(wstgRows, sec) {
  const active = wstgRows.filter(r => r.status);
  if (!active.length) return [];

  const title = sec?.title || 'OWASP WSTG Coverage';
  const done  = active.filter(r => r.status === 'done').length;
  const fail  = active.filter(r => r.status === 'fail').length;
  const na    = active.filter(r => r.status === 'na').length;

  const out = [
    sectionH2(title),
    p(`${done} completed  ·  ${fail} failed  ·  ${na} N/A  ·  ${active.length} total assessed`, { color: TEXT_MUTE, size: 20, italic: true }),
    spacer(80),
  ];

  out.push(...renderSectionExtras(sec));

  const STATUS_COLOR = { done: '15803D', fail: 'B91C1C', na: TEXT_MUTE };
  const STATUS_FILL  = { done: 'F0FDF4', fail: 'FEF2F2', na: 'F9FAFB' };

  out.push(tbl([
    headerRow([
      { text: 'Test ID', width: 18 },
      { text: 'Name',    width: 42 },
      { text: 'Status',  width: 10 },
      { text: 'Note',    width: 30 },
    ]),
    ...active.map((r, i) => new TableRow({ children: [
      tc(r.test_id,                             { fill: i%2?'FAFAFA':'FFFFFF', width: 18, size: 18, color: TEXT_MUTE }),
      tc(WSTG_NAMES[r.test_id] || r.test_id,   { fill: i%2?'FAFAFA':'FFFFFF', width: 42 }),
      tc(r.status.toUpperCase(),                { fill: STATUS_FILL[r.status] || 'FFFFFF', color: STATUS_COLOR[r.status] || TEXT_MUTE, width: 10, bold: true }),
      tc(r.note || '—',                         { fill: i%2?'FAFAFA':'FFFFFF', width: 30, color: TEXT_MUTE }),
    ]})),
  ]));

  out.push(spacer(200), pageBreak());
  return out;
}

function buildTargets(targets, ports, sec, type) {
  if (!targets.length) return [];
  const title = sec?.title || 'Scope — Targets';
  const out   = [sectionH2(title)];

  out.push(...renderSectionExtras(sec));

  out.push(tbl([
    headerRow([
      { text: 'Host', width: 70 },
      { text: 'Type', width: 30 },
    ]),
    ...targets.map((t, i) => dataRow([
      { text: t.host, width: 70, bold: true },
      { text: t.type, width: 30, color: TEXT_MUTE },
    ], { shaded: i % 2 === 1 })),
  ]));

  if (type === 'technical' && ports.length) {
    const portsByTarget = {};
    ports.forEach(p => {
      if (!portsByTarget[p.target_id]) portsByTarget[p.target_id] = [];
      portsByTarget[p.target_id].push(p);
    });

    targets.forEach(t => {
      const tPorts = portsByTarget[t.id];
      if (!tPorts?.length) return;

      out.push(spacer(160));
      out.push(sectionH3(`${t.host} — Open Ports`));
      out.push(tbl([
        headerRow([
          { text: 'Port',     width: 12 },
          { text: 'Protocol', width: 12 },
          { text: 'State',    width: 12 },
          { text: 'Service',  width: 20 },
          { text: 'Version',  width: 24 },
          { text: 'Notes',    width: 20 },
        ]),
        ...tPorts.map((p, i) => dataRow([
          { text: String(p.port),   width: 12, bold: true },
          { text: p.protocol,       width: 12, color: TEXT_MUTE },
          { text: p.state,          width: 12 },
          { text: p.service || '—', width: 20 },
          { text: p.version || '—', width: 24, color: TEXT_MUTE },
          { text: p.notes   || '—', width: 20, color: TEXT_MUTE },
        ], { shaded: i % 2 === 1 })),
      ]));
    });
  }

  return out;
}

function buildCustomSection(sec) {
  if (!sec.content?.trim() && !(sec.children || []).filter(c => c.visible !== false).length) return [];

  const out = [sectionH2(sec.title || 'Section')];

  if (sec.pageBreak) {
    // page break is applied at the heading level — already handled by Word styles
  }

  if (sec.content?.trim()) {
    out.push(...htmlToDocx(sec.content));
    out.push(spacer(80));
  }

  const subs = (sec.children || []).filter(c => c.visible !== false);
  subs.forEach(sub => {
    out.push(sectionH3(sub.title || 'Subsection'));
    if (sub.content?.trim()) out.push(...htmlToDocx(sub.content));
    out.push(spacer(60));
  });

  if (sec.pageBreak) out.push(pageBreak());
  return out;
}

// ── Main entry point ─────────────────────────────────────────────────

async function generateDocx({ project, vulns, targets, ports, wstgProgress, meta, type, sections }) {
  const children = [];

  // Cover
  children.push(...buildCover(project, vulns, meta, type));

  // Render sections in user-defined order (respects rptData.sections order & visibility)
  const BUILT_IN_TYPES = new Set(['exec-summary','findings-index','wstg','detailed-findings','risk-matrix','targets','risk-table']);

  const orderedSections = sections?.length ? sections : [
    { id:'exec-summary',      type:'exec-summary',      visible:true },
    { id:'findings-index',    type:'findings-index',    visible:true },
    { id:'wstg',              type:'wstg',              visible:true },
    { id:'detailed-findings', type:'detailed-findings', visible:true },
    { id:'targets',           type:'targets',           visible:true },
  ];

  for (const sec of orderedSections) {
    if (sec.visible === false) continue;

    switch (sec.type) {
      case 'exec-summary':
        children.push(...buildExecSummary(vulns, sec));
        break;
      case 'findings-index':
        children.push(...buildFindingsIndex(vulns, sec));
        break;
      case 'detailed-findings':
        if (type === 'technical') children.push(...buildDetailedFindings(vulns, sec));
        break;
      case 'wstg':
        children.push(...buildWstg(wstgProgress, sec));
        break;
      case 'targets':
        children.push(...buildTargets(targets, ports, sec, type));
        break;
      case 'risk-matrix':
      case 'risk-table':
        // visual-only sections — skip in DOCX
        break;
      case 'custom':
      default:
        if (!BUILT_IN_TYPES.has(sec.type)) {
          children.push(...buildCustomSection(sec));
        }
        break;
    }
  }

  const doc = new Document({
    title:       project.name,
    description: project.description || '',
    sections: [{
      properties: {
        page: {
          margin: {
            top:    convertInchesToTwip(1),
            right:  convertInchesToTwip(1),
            bottom: convertInchesToTwip(1),
            left:   convertInchesToTwip(1),
          },
        },
      },
      children,
    }],
  });

  return Packer.toBuffer(doc);
}

module.exports = { generateDocx };
