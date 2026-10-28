// Native, editable Word export of the report.
//
// Same content and rules as the PDF, which is built in the browser by
// buildReport() in frontend/export.html: section order and visibility, the
// report type forcing sections in (executive → risk matrix + roadmap, retest →
// retest sections) or out (detailed findings only in technical), scope gating,
// numbering, TOC, page breaks, meta.findingInclude, the per-finding vulnEdits
// and the C1/A1/M1/B1/I1 finding codes. When the report is in Free Edit
// (rptData.freeEditMd) the document is that Markdown instead.
//
// The document is built for editing, not for pixel parity: every block uses a
// named Word style (see docx/styles.js), lists use real numbering, the TOC is
// a real field and page numbers are PAGE / NUMPAGES fields.
//
// Labels are Spanish on purpose: they are the ones the PDF prints.

const {
  Document, Packer, Paragraph, TextRun, ImageRun,
  Table, TableRow, TableCell, TableOfContents,
  Header, Footer, PageNumber,
  AlignmentType, WidthType, BorderStyle, ShadingType, HeightRule,
  TableLayoutType, TextDirection, VerticalAlignTable,
  HorizontalPositionRelativeFrom, VerticalPositionRelativeFrom,
  HorizontalPositionAlign, VerticalPositionAlign, TextWrappingType,
} = require('docx');

const db = require('../db');
const { WSTG_NAMES, WSTG_CATEGORIES } = require('./wstgCatalog');
const { ImageStore, fitBox } = require('./docx/images');
const { useStyleBorders, htmlToBlocks, mdToHtml, contentToHtml, codeParagraph, PX } = require('./docx/html');
const {
  buildStylesXml, numberingConfig,
  RULE, HEAD_FILL, MUTED, PAGE_W, PAGE_H, MARGIN, CONTENT_W,
} = require('./docx/styles');

// ── Report vocabulary (mirrors frontend/export.html) ────────────────
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Info' };
const SEV_PREFIX = { critical: 'C', high: 'A', medium: 'M', low: 'B', info: 'I' };
const REM_LABEL = { open: 'Abierto', remediated: 'Remediado', not_remediated: 'No Remediado', verified_closed: 'Verificado' };
const RISK_LEVEL_LABEL = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Informativo' };
const RISK_BANNER_TEXT = {
  critical: 'Se identificaron vulnerabilidades críticas que representan un riesgo severo e inmediato para la organización. Se recomienda remediación urgente.',
  high:     'Se identificaron vulnerabilidades de alto impacto que deben priorizarse en el corto plazo para reducir la exposición al riesgo.',
  medium:   'El nivel de riesgo general es moderado. Existen hallazgos que conviene remediar dentro del ciclo habitual de mantenimiento.',
  low:      'El nivel de riesgo general es bajo. Los hallazgos identificados tienen impacto limitado sobre la organización.',
  info:     'No se identificaron vulnerabilidades explotables. Los hallazgos reportados son de carácter informativo.',
};
const DEFAULT_SECTIONS = [
  { id: 'exec-summary',        type: 'exec-summary',        title: 'Resumen Ejecutivo',            visible: true  },
  { id: 'retest-summary',      type: 'retest-summary',      title: 'Resumen de Retest',            visible: false },
  { id: 'findings-index',      type: 'findings-index',      title: 'Índice de Hallazgos',          visible: true  },
  { id: 'wstg',                type: 'wstg',                title: 'Cobertura OWASP WSTG',         visible: true  },
  { id: 'detailed-findings',   type: 'detailed-findings',   title: 'Hallazgos Detallados',         visible: true  },
  { id: 'retest-findings',     type: 'retest-findings',     title: 'Hallazgos — Estado de Retest', visible: false },
  { id: 'risk-matrix',         type: 'risk-matrix',         title: 'Matriz de Riesgo',             visible: false },
  { id: 'remediation-roadmap', type: 'remediation-roadmap', title: 'Hoja de Ruta de Remediación',  visible: false },
  { id: 'targets',             type: 'targets',             title: 'Alcance — Objetivos',          visible: true  },
  { id: 'risk-table',          type: 'risk-table',          title: 'Clasificación de Riesgo',      visible: false },
];
const REMOVED_IDS = new Set(['intro', 'scope', 'methodology', 'disclaimer', 'contact']);
const DEFAULT_COVER_FIELDS = { date: true, target: true, preparedBy: true, organization: true, scope: true, version: true, totalFindings: true, wstgCoverage: true };
const PRIORITY_ORDER = ['immediate', 'short', 'medium', 'routine'];
const PRIORITY_LABEL = { immediate: 'Inmediato (0–7 días)', short: 'Corto Plazo (2–4 semanas)', medium: 'Mediano Plazo (1–3 meses)', routine: 'Mantenimiento Rutinario' };
const PRIORITY_COLOR = { immediate: 'EF4444', short: 'F97316', medium: 'EAB308', routine: '6B7280' };
const defaultPriority = sev => sev === 'critical' ? 'immediate' : sev === 'high' ? 'short' : sev === 'medium' ? 'medium' : 'routine';
const RISK_CELL = [
  ['bajo',  'bajo',  'bajo',    'medio',   'medio'  ],
  ['bajo',  'bajo',  'medio',   'alto',    'alto'   ],
  ['bajo',  'medio', 'alto',    'alto',    'critico'],
  ['medio', 'alto',  'critico', 'critico', 'critico'],
];
const RISK_COLORS  = { bajo: '16A34A', medio: 'CA8A04', alto: 'EA580C', critico: 'DC2626' };
const RISK_LABELS  = { bajo: 'Bajo', medio: 'Medio', alto: 'Alto', critico: 'Crítico' };
const IMPACT_MAP   = { critical: 4, high: 3, medium: 2, low: 1, info: 1 };
const IMPACT_NAMES = { 4: 'Crítico', 3: 'Alto', 2: 'Medio', 1: 'Bajo' };
const PROB_LABELS  = ['Muy Baja', 'Baja', 'Moderada', 'Alta', 'Muy Alta'];
const FINDING_INCLUDE_DEFAULTS = { desc: true, rem: true, pay: true, notes: false, evid: true, retest: true };
const REPORT_SCOPES = ['all', 'vulns', 'wstg'];
const REPORT_TYPES  = ['technical', 'executive', 'retest'];

// Section gating — same tables as sectionState() in export.html.
const FORCE_BY_TYPE = {
  executive: new Set(['risk-matrix', 'remediation-roadmap']),
  retest:    new Set(['retest-summary', 'retest-findings']),
};
const SCOPE_EXCLUDES = {
  wstg:  new Set(['exec-summary', 'retest-summary', 'findings-index', 'detailed-findings', 'retest-findings', 'risk-matrix', 'remediation-roadmap']),
  vulns: new Set(['wstg']),
};
const TYPE_ALLOWS = {
  'exec-summary':      t => t !== 'retest',
  'retest-summary':    t => t === 'retest',
  'detailed-findings': t => t === 'technical',
  'retest-findings':   t => t === 'retest',
};
const NEEDS_FINDINGS = new Set(['findings-index', 'detailed-findings', 'retest-findings', 'risk-matrix', 'remediation-roadmap']);
const RENDERED_TYPES = new Set(['custom', 'exec-summary', 'retest-summary', 'findings-index', 'wstg', 'detailed-findings', 'retest-findings', 'risk-matrix', 'remediation-roadmap', 'targets', 'risk-table']);

function sectionIncluded(sec, scope, type, nVulns, nTargets) {
  const forced   = !!FORCE_BY_TYPE[type]?.has(sec.type);
  const shown    = !!sec.visible || forced;
  const scopeOff = !!SCOPE_EXCLUDES[scope]?.has(sec.type);
  const typeOff  = TYPE_ALLOWS[sec.type] ? !TYPE_ALLOWS[sec.type](type) : false;
  let hasData = RENDERED_TYPES.has(sec.type);
  if (NEEDS_FINDINGS.has(sec.type)) hasData = nVulns > 0;
  else if (sec.type === 'targets') hasData = nTargets > 0;
  else if (sec.type === 'custom') hasData = !!sec.content || (sec.children || []).some(c => c.visible !== false);
  return shown && !scopeOff && !typeOff && hasData;
}

// ── Colours ─────────────────────────────────────────────────────────
const SEV_COLOR = {
  critical: { text: 'B91C1C', fill: 'FEF2F2', bar: 'DC2626' },
  high:     { text: 'C2410C', fill: 'FFF7ED', bar: 'F97316' },
  medium:   { text: 'A16207', fill: 'FEFCE8', bar: 'EAB308' },
  low:      { text: '15803D', fill: 'F0FDF4', bar: '059669' },
  info:     { text: '4B5563', fill: 'F3F4F6', bar: '6B7280' },
};
const STATUS_COLOR = {
  verified_closed: { text: '15803D', fill: 'F0FDF4' },
  remediated:      { text: 'A16207', fill: 'FEFCE8' },
  not_remediated:  { text: 'B91C1C', fill: 'FEF2F2' },
  open:            { text: '4B5563', fill: 'F3F4F6' },
  pending:         { text: '4B5563', fill: 'F3F4F6' },
};
const CVSS_COLOR = { critical: 'DC2626', high: 'F97316', medium: 'F59E0B', low: '059669', info: '64748B' };
const DEFAULT_ACCENT = '7C3AED';

const hexColor = c => {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(c || '').trim());
  return m ? m[1].toUpperCase() : null;
};

// ── Small building blocks ───────────────────────────────────────────
const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const line = (color, size = 4) => ({ style: BorderStyle.SINGLE, size, color });
const shade = fill => ({ type: ShadingType.CLEAR, fill, color: 'auto' });

const run = (text, o = {}) => new TextRun({ text: String(text ?? ''), ...o });

function para(children, o = {}) {
  return new Paragraph({ style: o.style || 'Normal', ...o, children: Array.isArray(children) ? children : [children] });
}
const textPara = (text, style = 'Normal', o = {}) => para([run(text)], { style, ...o });

// Chip: the coloured severity / status label.
function chip(label, color) {
  return run(` ${String(label).toUpperCase()} `, { style: 'EtiquetaSeveridad', color: color.text, shading: shade(color.fill) });
}
const sevChip = sev => chip(SEV_LABEL[sev] || sev, SEV_COLOR[sev] || SEV_COLOR.info);
const statusChip = (key, label) => chip(label, STATUS_COLOR[key] || STATUS_COLOR.open);

function table({ style = 'TablaResility', widths, rows, borders }) {
  const t = new Table({
    style,
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    columnWidths: widths,
    layout: TableLayoutType.FIXED,
    borders,
    rows,
  });
  return borders ? t : useStyleBorders(t);
}

function cell(children, o = {}) {
  const kids = (Array.isArray(children) ? children : [children]).filter(Boolean);
  return new TableCell({
    ...o,
    width: o.width ? { size: o.width, type: WidthType.DXA } : undefined,
    shading: o.fill ? shade(o.fill) : undefined,
    children: kids.length ? kids : [para([], { style: 'TablaTexto' })],
  });
}

// Plain header row for a "Tabla Resility".
function headRow(labels, widths) {
  return new TableRow({
    tableHeader: true,
    children: labels.map((l, i) => cell(textPara(l, 'TablaCabecera'), { width: widths[i], fill: HEAD_FILL })),
  });
}

function fieldLabel(text) { return textPara(text, 'EtiquetaCampo'); }

// Multi-line plain text → one paragraph with line breaks.
function multiline(text, style = 'Normal') {
  const lines = String(text ?? '').replace(/\r\n?/g, '\n').split('\n');
  return para(lines.map((l, i) => run(l, { break: i ? 1 : undefined })), { style });
}

// ── Report data normalisation (getReportData in export.html) ────────
function parseReport(rptData) {
  if (rptData && typeof rptData === 'object') return rptData;
  try { return JSON.parse(rptData || '{}') || {}; } catch { return {}; }
}

function normalizeReport(raw) {
  const data = { ...raw };
  let sections = Array.isArray(raw.sections) ? raw.sections.map(s => ({ ...s })) : null;
  const meta = raw.meta && typeof raw.meta === 'object' ? { ...raw.meta } : {};
  if (!sections) {
    sections = DEFAULT_SECTIONS.map(s => {
      const sec = { ...s };
      if (s.id === 'risk-table') sec.visible = !!raw.showRiskTable;
      return sec;
    });
    // Old flat format kept these at the top level.
    for (const k of ['preparedBy', 'organization', 'version', 'classification']) if (meta[k] == null && raw[k]) meta[k] = raw[k];
    if (meta.showToc == null && raw.showToc != null) meta.showToc = !!raw.showToc;
  }
  if (!meta.coverFields) meta.coverFields = { ...DEFAULT_COVER_FIELDS };
  sections = sections.filter(s => s && !REMOVED_IDS.has(s.id) && !REMOVED_IDS.has(s.type));
  const existing = new Set(sections.map(s => s.id));
  DEFAULT_SECTIONS.forEach((def, idx) => {
    if (existing.has(def.id)) return;
    const prev = DEFAULT_SECTIONS[idx - 1];
    const after = prev ? sections.findIndex(s => s.id === prev.id) : -1;
    sections.splice(after + 1, 0, { ...def });
  });
  data.meta = meta;
  data.sections = sections;
  data.vulnEdits = raw.vulnEdits && typeof raw.vulnEdits === 'object' ? raw.vulnEdits : {};
  return data;
}

function findingIncludeOf(meta) {
  const fi = meta?.findingInclude || {};
  const out = {};
  for (const k in FINDING_INCLUDE_DEFAULTS) out[k] = typeof fi[k] === 'boolean' ? fi[k] : FINDING_INCLUDE_DEFAULTS[k];
  return out;
}

function esDate(d = new Date()) {
  try { return d.toLocaleDateString('es-ES', { day: '2-digit', month: 'long', year: 'numeric' }); }
  catch { return d.toISOString().slice(0, 10); }
}

// WSTG catalogue grouped by category, in the frontend's order.
function wstgCatalog() {
  const cats = {};
  for (const id of Object.keys(WSTG_NAMES)) {
    const pfx = /^WSTG-([A-Z]+)-/.exec(id)?.[1];
    if (!pfx) continue;
    (cats[pfx] ||= { name: WSTG_CATEGORIES[pfx] || pfx, tests: [] }).tests.push({ id, name: WSTG_NAMES[id] });
  }
  return Object.values(cats);
}

// ── The writer ──────────────────────────────────────────────────────
class ReportWriter {
  constructor(input) {
    Object.assign(this, input);
    this.out = [];
    this.toc = [];
    this.breakNext = false;
    this.secNum = 0;
  }

  push(...blocks) { for (const b of blocks.flat()) if (b) this.out.push(b); }

  html(html, o = {}) {
    return htmlToBlocks(html, { ...this.ctx, width: o.width || CONTENT_W }, { style: o.style, align: o.align });
  }

  heading(text, level = 1, { pageBreak = false, toc = true } = {}) {
    const brk = pageBreak || this.breakNext;
    this.breakNext = false;
    if (toc && level <= 2) this.toc.push({ title: text, level });
    return para([run(text)], { style: level === 1 ? 'Heading1' : level === 2 ? 'Heading2' : 'Heading3', pageBreakBefore: brk || undefined });
  }

  sectionHeading(sec) {
    this.secNum++;
    const title = this.meta.numbering ? `${this.secNum}. ${sec.title || ''}` : (sec.title || '');
    this.push(this.heading(title, 1, { pageBreak: !!sec.pageBreak }));
    if (sec.description) this.push(this.html(contentToHtml(sec.description)));
  }

  subsections(sec) {
    const subs = (sec.children || []).filter(c => c.visible !== false);
    subs.forEach((sub, si) => {
      const title = this.meta.numbering ? `${this.secNum}.${si + 1} ${sub.title || ''}` : (sub.title || '');
      this.push(this.heading(title, 2));
      if (sub.content) this.push(this.html(contentToHtml(sub.content)));
    });
  }

  note(text) { this.push(textPara(text, 'Nota')); }

  // ── Cover ──────────────────────────────────────────────────────
  cover() {
    const { project: p, meta: m } = this;
    const logoSrc = m.coverLogoBase64 || m.clientLogoUrl || p.logo_url || null;
    const title = m.coverTitle || p.name || '';
    const blocks = [];
    blocks.push(para([], { style: 'Normal', spacing: { before: 1800, after: 0 } }));
    const logo = typeof logoSrc === 'string' && logoSrc.startsWith('data:') ? this.images.get(logoSrc) : null;
    if (logo) {
      blocks.push(para([new ImageRun({ type: logo.type, data: logo.data, transformation: fitBox(logo.width, logo.height, 300, 110) })], { style: 'Imagen' }));
    } else {
      blocks.push(para([run((title || '?')[0].toUpperCase(), { bold: true, size: 96, color: this.accent })], { style: 'Imagen' }));
    }
    blocks.push(textPara(m.coverTypeLabel || 'Informe de Evaluación de Seguridad', 'PortadaTipo'));
    blocks.push(textPara(title, 'PortadaTitulo'));
    if (m.coverSubtitle) blocks.push(textPara(m.coverSubtitle, 'PortadaCliente'));
    if (m.clientName) blocks.push(para([run(m.clientName, { italics: true })], { style: 'PortadaCliente' }));
    blocks.push(textPara(m.classification || 'Confidencial', 'PortadaClasificacion'));
    this.push(blocks);
    this.breakNext = true;
  }

  // Cover metadata rows (two items per row, label + value), shown at the
  // bottom of the cover through its own first-page footer.
  coverMetaTable() {
    const { project: p, meta: m, vulns, scope, wstg } = this;
    const cf = m.coverFields || {};
    const items = [];
    if (cf.date          !== false)                   items.push(['Fecha', this.date]);
    if (cf.target        !== false && p.target)       items.push(['Objetivo', p.target]);
    if (cf.preparedBy    !== false && m.preparedBy)   items.push(['Preparado por', m.preparedBy]);
    if (cf.organization  !== false && m.organization) items.push(['Organización', m.organization]);
    if (cf.scope         !== false && p.description)  items.push(['Alcance', p.description]);
    if (cf.version       !== false && m.version)      items.push(['Versión', m.version]);
    if (cf.totalFindings !== false && scope !== 'wstg')  items.push(['Total hallazgos', String(vulns.length)]);
    if (cf.wstgCoverage  !== false && scope !== 'vulns') items.push(['Cobertura WSTG', `${wstg.pct}% (${wstg.tested}/${wstg.total})`]);
    if (!items.length) return null;
    const widths = [1500, 3036, 1500, 3036];
    const rows = [];
    for (let i = 0; i < items.length; i += 2) {
      const cells = [];
      [items[i], items[i + 1]].forEach((it, k) => {
        cells.push(cell(it ? textPara(it[0], 'PortadaEtiqueta') : null, { width: widths[k * 2], verticalAlign: VerticalAlignTable.CENTER }));
        cells.push(cell(it ? textPara(it[1], 'PortadaValor') : null, { width: widths[k * 2 + 1], verticalAlign: VerticalAlignTable.CENTER }));
      });
      rows.push(new TableRow({ children: cells, height: { value: 420, rule: HeightRule.ATLEAST } }));
    }
    return table({
      style: 'TablaSinBordes', widths, rows,
      borders: { top: line(RULE), bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
    });
  }

  // ── Sections ───────────────────────────────────────────────────
  renderSections() {
    const { sections, type, scope, vulns, targets } = this;
    const visible = sections.filter(s => s.visible
      || (type === 'executive' && FORCE_BY_TYPE.executive.has(s.type))
      || (type === 'retest' && FORCE_BY_TYPE.retest.has(s.type)));
    for (const sec of visible) {
      if (!sectionIncluded(sec, scope, type, vulns.length, targets.length)) continue;
      const fn = {
        'custom':              () => this.custom(sec),
        'exec-summary':        () => this.execSummary(sec),
        'retest-summary':      () => this.retestSummary(sec),
        'findings-index':      () => this.findingsIndex(sec),
        'wstg':                () => this.wstgSection(sec),
        'detailed-findings':   () => this.detailedFindings(sec),
        'retest-findings':     () => this.retestFindings(sec),
        'risk-matrix':         () => this.riskMatrix(sec),
        'remediation-roadmap': () => this.roadmap(sec),
        'targets':             () => this.targetsSection(sec),
        'risk-table':          () => this.riskTable(sec),
      }[sec.type];
      if (fn) fn();
    }
    this.methodology();
  }

  custom(sec) {
    this.secNum++;
    const title = this.meta.numbering ? `${this.secNum}. ${sec.title || ''}` : (sec.title || '');
    this.push(this.heading(title, 1, { pageBreak: !!sec.pageBreak }));
    if (sec.content) this.push(this.html(contentToHtml(sec.content)));
    this.subsections(sec);
  }

  execSummary(sec) {
    const { vulns, bySev, type } = this;
    this.sectionHeading(sec);
    if (!vulns.length) { this.note('Sin hallazgos registrados para este proyecto.'); this.subsections(sec); return; }
    const level = SEV_ORDER.find(s => bySev[s].length) || null;
    if (type === 'executive' && level) {
      const c = SEV_COLOR[level];
      this.push(table({
        style: 'TablaConteo', widths: [2200, CONTENT_W - 2200],
        rows: [new TableRow({ children: [
          cell([textPara('Riesgo General', 'PortadaEtiqueta'), para([run(RISK_LEVEL_LABEL[level], { bold: true, size: 32, color: c.text })], { style: 'TablaTexto' })], { width: 2200, fill: c.fill, verticalAlign: VerticalAlignTable.CENTER }),
          cell(textPara(RISK_BANNER_TEXT[level], 'TablaTexto'), { width: CONTENT_W - 2200, fill: c.fill, verticalAlign: VerticalAlignTable.CENTER }),
        ] })],
      }), para([], { spacing: { after: 120 } }));
    }
    this.push(this.countCards(SEV_ORDER.filter(s => bySev[s].length).map(s => ({
      n: bySev[s].length, label: SEV_LABEL[s], color: SEV_COLOR[s],
    }))));
    if (type === 'executive') {
      const ch = [...bySev.critical, ...bySev.high];
      if (ch.length) {
        this.push(this.heading('Hallazgos Críticos y de Alto Riesgo', 3));
        ch.forEach(v => {
          const impact = this.edit(v).businessImpact || '';
          this.push(this.card(v.severity, [
            para([sevChip(v.severity), run('  '), run(this.code(v), { style: 'CodigoHallazgo' }), run('  '), run(v.name)], { style: 'HallazgoTitulo' }),
          ], [impact ? multiline(impact) : textPara('Impacto de negocio pendiente de completar.', 'Nota')]));
        });
      }
    }
    this.subsections(sec);
  }

  // Count cards + proportional bar + legend (exec and retest summaries).
  countCards(items) {
    if (!items.length) return [];
    const total = items.reduce((a, i) => a + i.n, 0);
    const w = Math.floor(CONTENT_W / items.length);
    const widths = items.map(() => w);
    const cards = table({
      style: 'TablaConteo', widths,
      rows: [new TableRow({ children: items.map(i => cell([
        para([run(String(i.n), { bold: true, size: 40, color: i.color.text })], { style: 'TablaTexto' }),
        para([run(i.label.toUpperCase(), { color: i.color.text })], { style: 'PortadaEtiqueta' }),
      ], { width: w, fill: i.color.fill })) })],
    });
    let left = CONTENT_W;
    const barW = items.map((i, k) => {
      const v = k === items.length - 1 ? left : Math.max(120, Math.round(CONTENT_W * i.n / total));
      left -= v;
      return v;
    });
    const bar = table({
      style: 'TablaSinBordes', widths: barW,
      borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: line('FFFFFF', 8) },
      rows: [new TableRow({ height: { value: 80, rule: HeightRule.EXACT }, children: items.map((i, k) => cell(para([run('', { size: 2 })], { style: 'TablaTexto' }), { width: barW[k], fill: i.color.bar || i.color.text })) })],
    });
    const legend = para(items.flatMap((i, k) => [
      run('● ', { color: i.color.bar || i.color.text }), run(`${i.label} (${i.n})${k < items.length - 1 ? '     ' : ''}`, { color: MUTED, size: 17 }),
    ]), { style: 'TablaTexto', spacing: { before: 80, after: 200 } });
    return [cards, para([], { style: 'TablaTexto', spacing: { after: 60 } }), bar, legend];
  }

  retestSummary(sec) {
    const { vulns } = this;
    this.sectionHeading(sec);
    if (!vulns.length) { this.note('Sin hallazgos registrados para este proyecto.'); this.subsections(sec); return; }
    const cnt = { open: 0, remediated: 0, not_remediated: 0, verified_closed: 0 };
    vulns.forEach(v => { const s = v.remediation_status || 'open'; if (cnt[s] !== undefined) cnt[s]++; });
    const BAR = { verified_closed: '059669', remediated: 'EAB308', not_remediated: 'EF4444', open: '6B7280' };
    const CARD = [['verified_closed', 'Verificado', 'low'], ['remediated', 'Remediado', 'medium'], ['not_remediated', 'No Remediado', 'critical'], ['open', 'Abierto', 'info']];
    this.push(this.countCards(CARD.filter(([k]) => cnt[k]).map(([k, label, sev]) => ({
      n: cnt[k], label, color: { ...SEV_COLOR[sev], bar: BAR[k] },
    }))));
    this.subsections(sec);
  }

  findingsIndex(sec) {
    this.sectionHeading(sec);
    const widths = [700, 1300, CONTENT_W - 700 - 1300 - 1650 - 1500, 1650, 1500];
    const rows = [headRow(['ID', 'Severidad', 'Vulnerabilidad', 'Categoría', 'Remediación'], widths)];
    SEV_ORDER.forEach(sev => this.bySev[sev].forEach(v => {
      const rs = v.remediation_status || 'open';
      rows.push(new TableRow({ cantSplit: true, children: [
        cell(para([run(this.code(v), { style: 'CodigoHallazgo' })], { style: 'TablaTexto' }), { width: widths[0] }),
        cell(para([sevChip(sev)], { style: 'TablaTexto' }), { width: widths[1] }),
        cell(para([run(v.name, { bold: true })], { style: 'TablaTexto' }), { width: widths[2] }),
        cell(para([run(v.category || 'Custom', { font: 'Consolas', size: 16 })], { style: 'TablaTexto' }), { width: widths[3] }),
        cell(para([statusChip(rs, REM_LABEL[rs] || rs)], { style: 'TablaTexto' }), { width: widths[4] }),
      ] }));
    }));
    this.push(table({ widths, rows }));
    this.subsections(sec);
  }

  wstgSection(sec) {
    const { wstg, type, inc } = this;
    this.sectionHeading(sec);
    this.push(para([
      run(`${wstg.tested}/${wstg.total}`, { bold: true }), run(' pruebas completadas  ·  '),
      run(`${wstg.done} aprobadas`, { bold: true, color: '15803D' }), run('  ·  '),
      run(`${wstg.fail} hallazgos`, { bold: true, color: 'B91C1C' }),
    ]));
    const widths = [CONTENT_W - 1100 * 3 - 1300, 1100, 1100, 1100, 1300];
    const rows = [headRow(['Categoría', 'Realizadas', 'Total', 'Hallazgos', 'Progreso'], widths)];
    const center = t => para([run(t)], { style: 'TablaTexto', alignment: AlignmentType.CENTER });
    wstgCatalog().forEach(cat => {
      const t = cat.tests.length;
      const d = cat.tests.filter(x => this.wstgProgress[x.id]?.status === 'done').length;
      const f = cat.tests.filter(x => this.wstgProgress[x.id]?.status === 'fail').length;
      if (!d && !f) return;
      const pct = t ? Math.round((d + f) / t * 100) : 0;
      rows.push(new TableRow({ cantSplit: true, children: [
        cell(textPara(cat.name, 'TablaTexto'), { width: widths[0] }),
        cell(center(String(d + f)), { width: widths[1] }),
        cell(center(String(t)), { width: widths[2] }),
        cell(para([run(f ? String(f) : '—', { color: f ? 'B91C1C' : undefined, bold: !!f })], { style: 'TablaTexto', alignment: AlignmentType.CENTER }), { width: widths[3] }),
        cell(para([run(`${pct}%`, { font: 'Consolas', size: 16 })], { style: 'TablaTexto', alignment: AlignmentType.CENTER }), { width: widths[4] }),
      ] }));
    });
    this.push(table({ widths, rows }));

    const failed = [];
    wstgCatalog().forEach(cat => cat.tests.forEach(t => {
      const prog = this.wstgProgress[t.id];
      if (prog?.status === 'fail') failed.push({ cat: cat.name, test: t, prog });
    }));
    if (failed.length && type === 'technical') {
      this.push(this.heading(`Hallazgos Encontrados (${failed.length})`, 3));
      failed.forEach(({ cat, test, prog }) => {
        const host = prog.target_id ? this.targets.find(t => t.id === prog.target_id)?.host : null;
        const linked = prog.linked_vuln_id ? this.vulns.find(v => v.id === prog.linked_vuln_id) : null;
        const body = [];
        const meta = [cat, host, linked ? `→ ${linked.name}` : null].filter(Boolean).join('  ·  ');
        if (inc.desc && prog.description) body.push(fieldLabel('Descripción'), ...this.html(mdToHtml(prog.description), { width: CONTENT_W - 500 }));
        if (inc.rem && prog.remediation) body.push(fieldLabel('Remediación'), ...this.html(mdToHtml(prog.remediation), { width: CONTENT_W - 500 }));
        if (inc.notes && prog.note) body.push(multiline(prog.note, 'Nota'));
        this.push(this.card('critical', [
          para([chip(test.id, SEV_COLOR.critical), run('  '), run(test.name)], { style: 'HallazgoTitulo' }),
          textPara(meta, 'HallazgoMeta'),
        ], body));
      });
    }
    this.subsections(sec);
  }

  // A finding card ("Tabla Hallazgo"): header row + body row, left border in
  // the severity colour.
  card(sev, head, body, { borderColor } = {}) {
    const color = borderColor || SEV_COLOR[sev]?.bar || RULE;
    const rows = [new TableRow({ cantSplit: true, children: [cell(head, { width: CONTENT_W, fill: 'F9FAFB' })] })];
    if (body && body.length) rows.push(new TableRow({ children: [cell(body, { width: CONTENT_W })] }));
    return [
      table({
        style: 'TablaHallazgo', widths: [CONTENT_W], rows,
        borders: { top: line(RULE), bottom: line(RULE), right: line(RULE), left: line(color, 24), insideHorizontal: line(RULE), insideVertical: NONE },
      }),
      para([], { style: 'TablaTexto', spacing: { after: 200 } }),
    ];
  }

  severityGroup(sev) {
    const n = this.bySev[sev].length;
    this.push(para([sevChip(sev), run(`   ${n} hallazgo${n > 1 ? 's' : ''}`)], { style: 'GrupoSeveridad' }));
  }

  findingHeader(v, sev, metaParts) {
    const out = [para([sevChip(sev), run('  '), run(this.code(v), { style: 'CodigoHallazgo' }), run('  '), run(v.name || '')], { style: 'HallazgoTitulo' })];
    const parts = metaParts.filter(Boolean);
    if (parts.length) {
      out.push(para(parts.flatMap((p, i) => [...(i ? [run('  ·  ', { color: 'D1D5DB' })] : []), typeof p === 'string' ? run(p) : p]), { style: 'HallazgoMeta' }));
    }
    return out;
  }

  evidenceBlocks(list) {
    const maxPx = Math.floor((CONTENT_W - 480) / PX);
    return list.map(img => {
      const im = img?.data ? this.images.get(img.data) : null;
      if (!im) return textPara(`[imagen no disponible${img?.name ? `: ${img.name}` : ''}]`, 'Nota');
      return para([new ImageRun({
        type: im.type, data: im.data,
        transformation: fitBox(im.width, im.height, maxPx, 860),
        altText: img.name ? { name: String(img.name).slice(0, 120), description: String(img.name).slice(0, 200), title: String(img.name).slice(0, 120) } : undefined,
      })], { style: 'Imagen' });
    });
  }

  detailedFindings(sec) {
    const { inc } = this;
    this.sectionHeading(sec);
    const wstgForVuln = {};
    wstgCatalog().forEach(cat => cat.tests.forEach(t => {
      const lvid = this.wstgProgress[t.id]?.linked_vuln_id;
      if (lvid) (wstgForVuln[lvid] ||= []).push(t.id);
    }));
    const W = CONTENT_W - 480;
    SEV_ORDER.forEach(sev => {
      if (!this.bySev[sev].length) return;
      this.severityGroup(sev);
      this.bySev[sev].forEach(v => {
        const e = this.edit(v);
        const descHtml = e.description || mdToHtml(v.description || '');
        const remHtml  = e.remediation || mdToHtml(v.remediation || '');
        const notes    = v.notes || '';
        const evid     = Array.isArray(v.evidence) ? v.evidence : [];
        const remStatus = v.remediation_status || 'open';
        const wl = wstgForVuln[v.id] || [];
        const tags = Array.isArray(v.compliance_tags) ? v.compliance_tags : [];
        const head = this.findingHeader(v, sev, [
          v.cvss_score != null ? run(`CVSS ${(+v.cvss_score).toFixed(1)}`, { bold: true, color: CVSS_COLOR[sev] }) : null,
          v.cwe || null,
          tags.length ? run(`PCI-DSS: ${tags.map(t => t.control_id).join(', ')}`, { color: this.accent }) : null,
          v.category || null,
          v.target_host ? run(v.target_host, { color: this.accent }) : null,
          wl.length ? run(`WSTG: ${wl.join(', ')}`, { color: this.accent }) : null,
        ]);
        const body = [];
        if (inc.desc && descHtml) body.push(fieldLabel('Descripción'), ...this.html(descHtml, { width: W }));
        const payloads = Array.isArray(v.payloads) ? v.payloads : [];
        if (inc.pay && payloads.length) {
          body.push(fieldLabel('Payloads'));
          payloads.forEach(pl => body.push(codeParagraph(typeof pl === 'object' ? JSON.stringify(pl, null, 2) : String(pl), 'CodigoHTTP')));
        }
        const items = Array.isArray(v.items) ? v.items : [];
        if (items.length) {
          body.push(fieldLabel('Lista de verificación'));
          items.forEach((it, i) => body.push(textPara(`${v.checked_items?.[i] ? '[x]' : '[ ]'} ${it}`, 'TablaTexto')));
        }
        if (tags.length) {
          body.push(fieldLabel('Cobertura PCI-DSS'));
          tags.forEach(t => body.push(para([run(t.control_id || '', { bold: true, color: this.accent, font: 'Consolas' }), run(` — ${t.title || ''}`)], { style: 'TablaTexto' })));
        }
        if (inc.notes && notes) body.push(fieldLabel('Notas'), multiline(notes));
        if (inc.rem && remHtml) body.push(fieldLabel('Remediación'), ...this.html(remHtml, { width: W }));
        if (inc.retest && remStatus !== 'open') {
          body.push(fieldLabel('Retest'));
          body.push(para([statusChip(remStatus, REM_LABEL[remStatus] || remStatus), ...(v.retest_date ? [run(`  ${v.retest_date}`, { font: 'Consolas', size: 17, color: MUTED })] : [])], { style: 'TablaTexto', spacing: { after: 80 } }));
          if (v.retest_notes) body.push(...this.html(mdToHtml(v.retest_notes), { width: W }));
        }
        if (inc.evid && evid.length) body.push(fieldLabel('Evidencia'), ...this.evidenceBlocks(evid));
        const proofs = (Array.isArray(v.http_proofs) ? v.http_proofs : []).filter(pr => pr && pr.include !== false);
        if (proofs.length) {
          body.push(fieldLabel(`HTTP Proofs (${proofs.length})`));
          proofs.forEach((pr, idx) => {
            body.push(para([run(pr.method ? `${pr.method} — Proof #${idx + 1}` : `Proof #${idx + 1}`, { bold: true })], { style: 'HallazgoMeta', keepNext: true, spacing: { before: 80, after: 60 } }));
            if (pr.request?.trim())  body.push(textPara('Request', 'EtiquetaCampo', { spacing: { before: 40, after: 40 } }), codeParagraph(pr.request, 'CodigoHTTP', { numbered: true }));
            if (pr.response?.trim()) body.push(textPara('Response', 'EtiquetaCampo', { spacing: { before: 40, after: 40 } }), codeParagraph(pr.response, 'CodigoHTTP', { numbered: true }));
            if (pr.annotation?.trim()) body.push(...this.html(mdToHtml(pr.annotation), { width: W, style: 'Cita' }));
          });
        }
        this.push(this.card(sev, head, body.filter(Boolean)));
      });
    });
    this.subsections(sec);
  }

  retestFindings(sec) {
    this.sectionHeading(sec);
    const W = CONTENT_W - 480;
    SEV_ORDER.forEach(sev => {
      if (!this.bySev[sev].length) return;
      this.severityGroup(sev);
      this.bySev[sev].forEach(v => {
        const e = this.edit(v);
        const descHtml = e.description || mdToHtml(v.description || '');
        const remStatus = v.remediation_status || 'open';
        const evid = Array.isArray(v.evidence) ? v.evidence : [];
        const original = e.hideOriginalEvidence ? [] : evid.filter(i => (i?.phase || 'original') === 'original');
        const retest = evid.filter(i => i?.phase === 'retest');
        const head = this.findingHeader(v, sev, []);
        head.push(para([statusChip(remStatus, REM_LABEL[remStatus] || remStatus), ...(v.retest_date ? [run(`  ${v.retest_date}`)] : [])], { style: 'HallazgoMeta', spacing: { before: 60 } }));
        const body = [];
        if (descHtml) body.push(fieldLabel('Descripción'), ...this.html(descHtml, { width: W }));
        if (v.retest_notes) body.push(fieldLabel('Notas de Retest'), ...this.html(mdToHtml(v.retest_notes), { width: W }));
        if (original.length) body.push(fieldLabel('Evidencia Original'), ...this.evidenceBlocks(original));
        if (retest.length) body.push(fieldLabel('Evidencia de Retest'), ...this.evidenceBlocks(retest));
        this.push(this.card(sev, head, body));
      });
    });
    this.subsections(sec);
  }

  riskMatrix(sec) {
    this.sectionHeading(sec);
    const matrixVulns = this.vulns.filter(v => (v.severity || 'medium') !== 'info');
    const cellVulns = {};
    const riskCounts = { bajo: 0, medio: 0, alto: 0, critico: 0 };
    matrixVulns.forEach(v => {
      const impact = IMPACT_MAP[v.severity || 'medium'];
      if (!impact) return;
      const prob = Math.min(5, Math.max(1, Math.round(+this.edit(v).probability || 3)));
      const risk = RISK_CELL[impact - 1][prob - 1];
      (cellVulns[`${impact}_${prob}`] ||= []).push(this.code(v));
      riskCounts[risk]++;
    });
    const n = matrixVulns.length;
    this.push(para([run('Se identificaron '), run(String(n), { bold: true }), run(` hallazgo${n !== 1 ? 's' : ''} representados en la matriz según probabilidad e impacto.`)]));

    const LB = line('D1D5DB');
    const WHITE = line('FFFFFF', 16);
    const GREY = 'F3F4F6', GREY2 = 'F9FAFB';
    const widths = [420, 1100, 520, 1080, 1080, 1080, 1080, 1080, 1400];
    const allB = b => ({ top: b, bottom: b, left: b, right: b });
    const small = (t, o = {}) => para([run(t, { size: o.size || 17, bold: o.bold, color: o.color, font: o.mono ? 'Consolas' : undefined })], { style: 'TablaTexto', alignment: AlignmentType.CENTER });
    const blank = (w, span) => cell(null, { width: w, columnSpan: span, borders: allB(NONE) });
    const rows = [];
    [4, 3, 2, 1].forEach((impact, r) => {
      const rowCount = matrixVulns.filter(v => IMPACT_MAP[v.severity || 'medium'] === impact).length;
      const cells = [];
      if (r === 0) {
        cells.push(cell(small('IMPACTO', { bold: true }), { width: widths[0], rowSpan: 4, fill: GREY, borders: allB(LB), textDirection: TextDirection.BOTTOM_TO_TOP_LEFT_TO_RIGHT, verticalAlign: VerticalAlignTable.CENTER }));
      }
      cells.push(cell(small(IMPACT_NAMES[impact], { bold: true }), { width: widths[1], fill: GREY, borders: allB(LB), verticalAlign: VerticalAlignTable.CENTER }));
      cells.push(cell(small(rowCount ? String(rowCount) : '', { bold: true, mono: true, size: 20 }), { width: widths[2], fill: GREY2, borders: allB(LB), verticalAlign: VerticalAlignTable.CENTER }));
      for (let prob = 1; prob <= 5; prob++) {
        const risk = RISK_CELL[impact - 1][prob - 1];
        const ids = (cellVulns[`${impact}_${prob}`] || []).join(' ');
        cells.push(cell(small(ids, { bold: true, mono: true, color: 'FFFFFF' }), { width: widths[2 + prob], fill: RISK_COLORS[risk], borders: allB(WHITE), verticalAlign: VerticalAlignTable.CENTER }));
      }
      const rowRisk = RISK_CELL[impact - 1][4];
      cells.push(cell([small('Riesgo', { bold: true, color: 'FFFFFF', size: 16 }), small(RISK_LABELS[rowRisk], { bold: true, color: 'FFFFFF', size: 16 })], { width: widths[8], fill: RISK_COLORS[rowRisk], borders: allB(LB), verticalAlign: VerticalAlignTable.CENTER }));
      rows.push(new TableRow({ cantSplit: true, height: { value: 760, rule: HeightRule.ATLEAST }, children: cells }));
    });
    const axisRow = (fn, fill) => new TableRow({ cantSplit: true, children: [
      blank(widths[0] + widths[1] + widths[2], 3),
      ...[1, 2, 3, 4, 5].map(i => cell(fn(i), { width: widths[2 + i], fill, borders: allB(LB) })),
      blank(widths[8]),
    ] });
    rows.push(axisRow(i => small(String(i), { bold: true, mono: true }), GREY));
    rows.push(axisRow(i => small(PROB_LABELS[i - 1], { size: 15, color: '4B5563' }), GREY2));
    rows.push(new TableRow({ cantSplit: true, children: [
      blank(widths[0] + widths[1] + widths[2], 3),
      cell(small('PROBABILIDAD', { bold: true }), { width: widths.slice(3, 8).reduce((a, b) => a + b, 0), columnSpan: 5, fill: GREY, borders: allB(LB) }),
      blank(widths[8]),
    ] }));
    this.push(table({
      style: 'TablaSinBordes', widths, rows,
      borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
    }), para([], { spacing: { after: 240 } }));

    const RK = ['bajo', 'medio', 'alto', 'critico'];
    const sw = 1300;
    this.push(table({
      style: 'TablaResility', widths: RK.map(() => sw),
      rows: [
        new TableRow({ children: [cell(para([run('Hallazgos por Valoración de Riesgo', { bold: true })], { style: 'TablaTexto' }), { width: sw * 4, columnSpan: 4, fill: GREY })] }),
        new TableRow({ children: RK.map(r => cell(small(RISK_LABELS[r], { bold: true, color: 'FFFFFF' }), { width: sw, fill: RISK_COLORS[r] })) }),
        new TableRow({ children: RK.map(r => cell(small(String(riskCounts[r] || 0), { bold: true, color: 'FFFFFF', size: 30, mono: true }), { width: sw, fill: RISK_COLORS[r] })) }),
      ],
    }));
    this.subsections(sec);
  }

  roadmap(sec) {
    this.sectionHeading(sec);
    const buckets = Object.fromEntries(PRIORITY_ORDER.map(p => [p, []]));
    this.vulns.forEach(v => {
      const pr = this.edit(v).remediationPriority;
      const p = PRIORITY_ORDER.includes(pr) ? pr : defaultPriority(v.severity || 'medium');
      buckets[p].push(v);
    });
    const widths = [800, 1300, 3000, CONTENT_W - 800 - 1300 - 3000];
    PRIORITY_ORDER.forEach(p => {
      const list = buckets[p];
      if (!list.length) return;
      this.push(para([
        run('● ', { color: PRIORITY_COLOR[p] }), run(PRIORITY_LABEL[p], { bold: true, color: '111827' }),
        run(`   ${list.length} hallazgo${list.length > 1 ? 's' : ''}`, { font: 'Consolas', size: 16, color: MUTED }),
      ], { style: 'TablaTexto', keepNext: true, spacing: { before: 240, after: 100 } }));
      const rows = [headRow(['ID', 'Severidad', 'Hallazgo', 'Acción Recomendada'], widths)];
      list.forEach(v => {
        const sev = v.severity || 'medium';
        const action = this.edit(v).execAction || 'Acción recomendada pendiente de generar.';
        rows.push(new TableRow({ cantSplit: true, children: [
          cell(para([run(this.code(v) || '', { style: 'CodigoHallazgo' })], { style: 'TablaTexto' }), { width: widths[0] }),
          cell(para(SEV_COLOR[sev] ? [sevChip(sev)] : [run(sev)], { style: 'TablaTexto' }), { width: widths[1] }),
          cell(para([run(v.name, { bold: true })], { style: 'TablaTexto' }), { width: widths[2] }),
          cell(textPara(action, 'TablaTexto'), { width: widths[3] }),
        ] }));
      });
      this.push(table({ widths, rows }));
    });
    this.subsections(sec);
  }

  targetsSection(sec) {
    this.sectionHeading(sec);
    const { targets, type } = this;
    if (type === 'executive') {
      const widths = [3000, 1500, 1400, CONTENT_W - 5900];
      const rows = [headRow(['Host', 'Tipo', 'Estado', 'Notas'], widths)];
      targets.forEach(t => rows.push(new TableRow({ cantSplit: true, children: [
        cell(para([run(t.host, { bold: true, font: 'Consolas', size: 17 })], { style: 'TablaTexto' }), { width: widths[0] }),
        cell(para([run(t.type || '—', { font: 'Consolas', size: 16, color: MUTED })], { style: 'TablaTexto' }), { width: widths[1] }),
        cell(para([statusChip(t.status || 'pending', t.status || 'pending')], { style: 'TablaTexto' }), { width: widths[2] }),
        cell(multiline(t.notes || '', 'TablaTexto'), { width: widths[3] }),
      ] })));
      this.push(table({ widths, rows }));
    } else {
      const W = CONTENT_W - 480;
      targets.forEach(t => {
        const ports = this.ports[t.id] || [];
        const eps = this.endpoints[t.id] || [];
        const head = [para([
          run(t.host, { bold: true, font: 'Consolas' }), ...(t.type ? [run(`   ${t.type}`, { font: 'Consolas', size: 16, color: MUTED })] : []),
          run('   '), statusChip(t.status || 'pending', t.status || 'pending'),
        ], { style: 'HallazgoTitulo' })];
        const body = [];
        if (t.notes) body.push(fieldLabel('Notas'), multiline(t.notes));
        if (ports.length) {
          const w = [900, 1100, 1100, 2400, W - 5500];
          body.push(fieldLabel(`Puertos abiertos (${ports.length})`), table({ widths: w, rows: [
            headRow(['Puerto', 'Protocolo', 'Estado', 'Servicio', 'Versión'], w),
            ...ports.map(pt => new TableRow({ cantSplit: true, children: [
              cell(para([run(String(pt.port), { bold: true, font: 'Consolas' })], { style: 'TablaTexto' }), { width: w[0] }),
              cell(textPara(pt.protocol || 'tcp', 'TablaTexto'), { width: w[1] }),
              cell(textPara(pt.state || 'open', 'TablaTexto'), { width: w[2] }),
              cell(textPara(pt.service || '—', 'TablaTexto'), { width: w[3] }),
              cell(para([run(pt.version || '', { color: MUTED, size: 16 })], { style: 'TablaTexto' }), { width: w[4] }),
            ] })),
          ] }));
        }
        if (eps.length) {
          const w = [1000, 3600, 900, W - 5500];
          body.push(fieldLabel(`Endpoints (${eps.length})`), table({ widths: w, rows: [
            headRow(['Método', 'Ruta', 'Estado', 'Notas'], w),
            ...eps.map(ep => new TableRow({ cantSplit: true, children: [
              cell(para([run(ep.method || 'GET', { bold: true, font: 'Consolas', color: this.accent })], { style: 'TablaTexto' }), { width: w[0] }),
              cell(para([run(ep.path || '', { font: 'Consolas', size: 16 })], { style: 'TablaTexto' }), { width: w[1] }),
              cell(textPara(ep.status_code != null ? String(ep.status_code) : '', 'TablaTexto'), { width: w[2] }),
              cell(multiline(ep.notes || '', 'TablaTexto'), { width: w[3] }),
            ] })),
          ] }));
        }
        this.push(this.card(null, head, body, { borderColor: 'D1D5DB' }));
      });
    }
    this.subsections(sec);
  }

  riskTable(sec) {
    this.sectionHeading(sec);
    const widths = [1400, 1800, CONTENT_W - 3200];
    const ROWS = [
      ['critical', 'Critical', '9.0 – 10.0', 'Riesgo inmediato de explotación con potencial de compromiso total del sistema o fuga significativa de datos. Requiere remediación urgente.'],
      ['high',     'High',     '7.0 – 8.9',  'Vulnerabilidad significativa que podría permitir acceso no autorizado o interrupción grave del servicio. Debe tratarse de forma prioritaria.'],
      ['medium',   'Medium',   '4.0 – 6.9',  'Riesgo moderado que puede ser explotado bajo ciertas condiciones. Se recomienda remediación a corto plazo.'],
      ['low',      'Low',      '0.1 – 3.9',  'Problemas de impacto limitado. Deben abordarse dentro del mantenimiento rutinario de seguridad.'],
      ['info',     'Info',     'N/A',        'Hallazgos informativos sin impacto directo en seguridad. Útiles para el endurecimiento y alineación con buenas prácticas.'],
    ];
    this.push(table({ widths, rows: [
      headRow(['Nivel', 'Puntuación CVSS', 'Descripción'], widths),
      ...ROWS.map(([sev, label, score, desc]) => new TableRow({ cantSplit: true, children: [
        cell(para([chip(label, SEV_COLOR[sev])], { style: 'TablaTexto' }), { width: widths[0] }),
        cell(para([run(score, { font: 'Consolas' })], { style: 'TablaTexto' }), { width: widths[1] }),
        cell(textPara(desc, 'TablaTexto'), { width: widths[2] }),
      ] })),
    ] }));
    this.subsections(sec);
  }

  // Always appended by the PDF (outside the section list), except for the
  // WSTG-only scope; the failed checks list is technical-only.
  methodology() {
    if (this.scope === 'wstg') return;
    const methods = Object.values(this.methodProgress || {});
    if (!methods.length) return;
    this.push(this.heading('Progreso de Metodología', 1));
    methods.forEach(meth => {
      const tests = meth.tests || [];
      const failed = tests.map((t, i) => t.status === 'fail' ? i + 1 : null).filter(Boolean);
      const body = [];
      const total = meth.total || 0;
      if (total) {
        const items = [
          meth.done ? { n: meth.done, color: '059669' } : null,
          meth.fail ? { n: meth.fail, color: 'EF4444' } : null,
          total - meth.done - meth.fail > 0 ? { n: total - meth.done - meth.fail, color: 'E5E7EB' } : null,
        ].filter(Boolean);
        const W = CONTENT_W - 480;
        let left = W;
        const ws = items.map((it, k) => { const v = k === items.length - 1 ? left : Math.max(100, Math.round(W * it.n / total)); left -= v; return v; });
        body.push(table({
          style: 'TablaSinBordes', widths: ws,
          borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: line('FFFFFF', 8) },
          rows: [new TableRow({ height: { value: 80, rule: HeightRule.EXACT }, children: items.map((it, k) => cell(para([run('', { size: 2 })], { style: 'TablaTexto' }), { width: ws[k], fill: it.color })) })],
        }));
      }
      if (this.type === 'technical' && failed.length) {
        body.push(fieldLabel(`Verificaciones fallidas (${failed.length})`));
        body.push(para(failed.flatMap((n, i) => [...(i ? [run(' ')] : []), chip(`#${n}`, SEV_COLOR.critical)]), { style: 'TablaTexto' }));
      }
      this.push(this.card(null, [para([
        run(meth.name || '', { bold: true }),
        run(`     ${meth.done || 0} completados`, { font: 'Consolas', size: 16, color: '15803D' }),
        ...(meth.fail ? [run(`   ${meth.fail} fallidos`, { font: 'Consolas', size: 16, color: 'B91C1C' })] : []),
        run(`   ${total} total`, { font: 'Consolas', size: 16, color: MUTED }),
      ], { style: 'HallazgoTitulo' })], body, { borderColor: 'D1D5DB' }));
    });
  }

  edit(v) {
    const saved = this.vulnEdits[v.id] || {};
    return {
      description: saved.description || '',
      remediation: saved.remediation || '',
      businessImpact: saved.businessImpact || '',
      execAction: saved.execAction || '',
      probability: saved.probability ?? 3,
      remediationPriority: saved.remediationPriority || null,
      hideOriginalEvidence: !!saved.hideOriginalEvidence,
    };
  }

  code(v) { return this.codes[v.id] || ''; }
}

// ── Header / footer ─────────────────────────────────────────────────
function zone(meta, key) {
  const z = meta?.[key];
  if (!z || !z.enabled) return null;
  const cols = z.cols || {};
  return ['left', 'center', 'right'].map(k => cols[k] || { mode: 'text', text: '' });
}

const ALIGNS = [AlignmentType.LEFT, AlignmentType.CENTER, AlignmentType.RIGHT];

function zoneTable(cells) {
  const w = Math.floor(CONTENT_W / 3);
  const widths = [w, CONTENT_W - 2 * w, w];
  return table({
    style: 'TablaSinBordes', widths,
    borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
    rows: [new TableRow({ children: cells.map((c, i) => cell(c, { width: widths[i], verticalAlign: VerticalAlignTable.CENTER })) })],
  });
}

function pageNumberRuns(prefix) {
  return [new TextRun({ children: [`${prefix || 'Página'} `, PageNumber.CURRENT, ' de ', PageNumber.TOTAL_PAGES] })];
}

function zoneCell(col, i, images, style) {
  const mode = col?.mode;
  if ((mode === 'image' || mode === 'img') && col.img) {
    const im = images.get(col.img);
    if (!im) return para([], { style, alignment: ALIGNS[i] });
    return para([new ImageRun({ type: im.type, data: im.data, transformation: fitBox(im.width, im.height, 190, 30) })], { style, alignment: ALIGNS[i] });
  }
  if (mode === 'pagenum') return para(pageNumberRuns(col.text), { style, alignment: ALIGNS[i] });
  return para([run(col?.text || '')], { style, alignment: ALIGNS[i] });
}

function watermarkParagraph(wm) {
  if (!wm) return null;
  const size = 540;
  return new Paragraph({
    style: 'Header',
    spacing: { line: 20, lineRule: 'exact', after: 0 },
    children: [new ImageRun({
      type: 'svg', data: wm.svg,
      fallback: { type: 'png', data: wm.png },
      transformation: { width: size, height: size },
      altText: { name: 'Marca de agua', description: 'Marca de agua', title: 'Marca de agua' },
      floating: {
        horizontalPosition: { relative: HorizontalPositionRelativeFrom.PAGE, align: HorizontalPositionAlign.CENTER },
        verticalPosition: { relative: VerticalPositionRelativeFrom.PAGE, align: VerticalPositionAlign.CENTER },
        behindDocument: true,
        allowOverlap: true,
        lockAnchor: true,
        wrap: { type: TextWrappingType.NONE },
      },
    })],
  });
}

function buildHeader(meta, images, wm) {
  const cols = zone(meta, 'header');
  const kids = [];
  const w = watermarkParagraph(wm);
  if (w) kids.push(w);
  if (cols) kids.push(zoneTable(cols.map((c, i) => zoneCell(c, i, images, 'Header'))), para([], { style: 'Header' }));
  if (!kids.length) return null;
  return new Header({ children: kids });
}

// "Página X de Y" always lands somewhere: in the column set to page number,
// else in an empty centre column.
function buildFooter(meta, images) {
  const cols = zone(meta, 'footer');
  if (!cols) return null;
  const hasPageNum = cols.some(c => c?.mode === 'pagenum');
  const cells = cols.map((c, i) => {
    if (!hasPageNum && i === 1 && !(c?.text || '').trim() && !((c?.mode === 'image' || c?.mode === 'img') && c.img)) {
      return para(pageNumberRuns(), { style: 'Footer', alignment: AlignmentType.CENTER });
    }
    return zoneCell(c, i, images, 'Footer');
  });
  return new Footer({ children: [zoneTable(cells)] });
}

// ── Entry points ────────────────────────────────────────────────────
async function generateDocx({
  project, vulns = [], targets = [], ports = {}, endpoints = {}, wstgProgress = {}, methodProgress = {},
  rptData, report, type, scope,
}) {
  const data = normalizeReport(report || parseReport(rptData));
  const meta = data.meta;
  const reportType  = REPORT_TYPES.includes(type)   ? type  : (REPORT_TYPES.includes(meta.reportType)   ? meta.reportType  : 'technical');
  const reportScope = REPORT_SCOPES.includes(scope) ? scope : (REPORT_SCOPES.includes(meta.reportScope) ? meta.reportScope : 'all');
  const accent = hexColor(meta.accentColor) || DEFAULT_ACCENT;
  const freeEdit = typeof data.freeEditMd === 'string' && data.freeEditMd.trim() ? data.freeEditMd : null;

  // Arrays → lookups the writer uses.
  const portsBy = Array.isArray(ports) ? groupBy(ports, 'target_id') : ports;
  const epsBy   = Array.isArray(endpoints) ? groupBy(endpoints, 'target_id') : endpoints;
  const wp = Array.isArray(wstgProgress) ? Object.fromEntries(wstgProgress.map(r => [r.test_id, r])) : (wstgProgress || {});

  const bySev = {};
  SEV_ORDER.forEach(s => { bySev[s] = vulns.filter(v => (v.severity || 'medium') === s); });
  const codes = {};
  SEV_ORDER.forEach(s => bySev[s].forEach((v, i) => { codes[v.id] = `${SEV_PREFIX[s]}${i + 1}`; }));

  let wDone = 0, wFail = 0, wTotal = 0;
  wstgCatalog().forEach(c => c.tests.forEach(t => {
    wTotal++;
    const st = wp[t.id]?.status;
    if (st === 'done') wDone++;
    if (st === 'fail') wFail++;
  }));
  const wstg = { done: wDone, fail: wFail, total: wTotal, tested: wDone + wFail, pct: wTotal ? Math.round((wDone + wFail) / wTotal * 100) : 0 };

  // Every image the document may use, decoded/converted up front.
  const images = new ImageStore();
  try {
    for (const z of ['header', 'footer']) for (const c of zone(meta, z) || []) if (c?.img) images.add(c.img);
    if (freeEdit) {
      images.addFromHtml(freeEdit);
    } else {
      images.add(meta.coverLogoBase64 || meta.clientLogoUrl || project.logo_url);
      for (const s of data.sections) {
        images.addFromHtml(s.content); images.addFromHtml(s.description);
        for (const c of s.children || []) images.addFromHtml(c.content);
      }
      for (const e of Object.values(data.vulnEdits)) { images.addFromHtml(e?.description); images.addFromHtml(e?.remediation); }
      const inc = findingIncludeOf(meta);
      if (inc.evid || reportType === 'retest') {
        for (const v of vulns) for (const img of Array.isArray(v.evidence) ? v.evidence : []) images.add(img?.data);
      }
    }
    await images.prepare();
    const wm = meta.watermark?.enabled ? await images.watermark(meta.watermark.text) : null;

    const ctx = { images, width: CONTENT_W, counters: { ol: 0 } };
    let children, tocBlocks = [], coverFooter = null, titlePage = false;

    if (freeEdit) {
      children = htmlToBlocks(mdToHtml(freeEdit, { styled: true }), {
        ...ctx, headingMap: { h1: 'PortadaTitulo', h2: 'Heading1', h3: 'Heading2', h4: 'Heading3', h5: 'Heading4', h6: 'Heading4' },
      });
    } else {
      const w = new ReportWriter({
        project, meta, sections: data.sections, vulnEdits: data.vulnEdits,
        vulns, targets, ports: portsBy, endpoints: epsBy, wstgProgress: wp, methodProgress,
        type: reportType, scope: reportScope, inc: findingIncludeOf(meta),
        bySev, codes, wstg, images, ctx, accent, date: esDate(),
      });
      w.cover();
      // The PDF breaks after the cover; with a TOC that break belongs to the
      // TOC page, and the first section only breaks if it asks to.
      const willToc = !!meta.showToc && data.sections.some(sec => (sec.visible || FORCE_BY_TYPE[reportType]?.has(sec.type))
        && sectionIncluded(sec, reportScope, reportType, vulns.length, targets.length));
      if (willToc) w.breakNext = false;
      const coverEnd = w.out.length;
      w.renderSections();
      if (meta.showToc && w.toc.length) {
        tocBlocks = [
          para([run('Índice de Contenidos')], { style: 'TOCHeading', pageBreakBefore: true }),
          new TableOfContents('Índice de Contenidos', {
            hyperlink: true,
            headingStyleRange: '1-2',
            // \u: "Título 1/2" carry outline levels 1/2 (styles.js), so the
            // field finds them whatever name the reader's Word gives them.
            useAppliedParagraphOutlineLevel: true,
            cachedEntries: w.toc.map(t => ({ title: t.title, level: t.level })),
          }),
        ];
      }
      children = [...w.out.slice(0, coverEnd), ...tocBlocks, ...w.out.slice(coverEnd)];
      coverFooter = w.coverMetaTable();
      titlePage = true;
    }

    const header = buildHeader(meta, images, wm);
    const footer = buildFooter(meta, images);
    const firstHeaderKids = [watermarkParagraph(wm)].filter(Boolean);

    const doc = new Document({
      title: meta.coverTitle || project.name || 'Informe',
      subject: meta.coverTypeLabel || 'Informe de Evaluación de Seguridad',
      creator: meta.preparedBy || 'Flowdit',
      description: project.description || '',
      features: { updateFields: true },
      numbering: numberingConfig(),
      sections: [{
        properties: {
          titlePage,
          page: {
            size: { width: PAGE_W, height: PAGE_H },
            margin: { top: 1701, right: MARGIN, bottom: 1417, left: MARGIN, header: 567, footer: 567 },
          },
        },
        headers: {
          ...(header ? { default: header } : {}),
          ...(titlePage ? { first: new Header({ children: firstHeaderKids.length ? firstHeaderKids : [para([], { style: 'Header' })] }) } : {}),
        },
        footers: {
          ...(footer ? { default: footer } : {}),
          ...(titlePage ? { first: new Footer({ children: coverFooter ? [coverFooter] : [para([], { style: 'Footer' })] }) } : {}),
        },
        children: children.length ? children : [para([])],
      }],
    });

    return await Packer.toBuffer(doc, false, [{ path: 'word/styles.xml', data: buildStylesXml({ accent }) }]);
  } finally {
    await images.close();
  }
}

function groupBy(rows, key) {
  const out = {};
  for (const r of rows || []) (out[r[key]] ||= []).push(r);
  return out;
}

// Everything buildReport() reads from the app state, loaded the way the
// browser loads it (same queries/ordering as the routes it calls).
async function loadReportData(projectId) {
  const [{ rows: [project] }, { rows: vulns }, { rows: targets }, { rows: ports }, { rows: endpoints }, { rows: wstg }] = await Promise.all([
    db.query('SELECT * FROM projects WHERE id = $1', [projectId]),
    db.query(
      `SELECT cv.*, t.host AS target_host, t.type AS target_type
       FROM custom_vulns cv
       LEFT JOIN targets t ON t.id = cv.target_id
       WHERE cv.project_id = $1
       ORDER BY
         CASE cv.severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
           WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6
         END, cv.created_at`,
      [projectId]),
    db.query('SELECT * FROM targets WHERE project_id = $1 ORDER BY created_at', [projectId]),
    db.query(
      `SELECT tp.* FROM target_ports tp JOIN targets t ON t.id = tp.target_id
       WHERE t.project_id = $1 ORDER BY tp.port ASC`, [projectId]),
    db.query(
      `SELECT e.* FROM target_endpoints e JOIN targets t ON t.id = e.target_id
       WHERE t.project_id = $1 ORDER BY e.path ASC, e.method ASC`, [projectId]),
    db.query(
      `SELECT test_id, status, note, description, remediation, target_id, linked_vuln_id
       FROM wstg_progress WHERE project_id = $1`, [projectId]),
  ]);
  if (!project) throw new Error('Project not found');

  // Same shape as GET /methodologies/project-progress/:projectId.
  const methodProgress = {};
  const activeIds = project.active_methodology_ids || [];
  if (activeIds.length) {
    const [{ rows: methods }, { rows: progress }] = await Promise.all([
      db.query('SELECT id, name, tests FROM methodologies WHERE id = ANY($1)', [activeIds]),
      db.query(
        `SELECT methodology_id, test_idx, status FROM methodology_progress
         WHERE project_id = $1 AND methodology_id = ANY($2)`, [projectId, activeIds]),
    ]);
    methods.forEach(m => {
      const tests = m.tests || [];
      const prog = progress.filter(p => p.methodology_id === m.id);
      methodProgress[m.id] = {
        name: m.name,
        total: tests.length,
        done: prog.filter(p => p.status === 'done').length,
        fail: prog.filter(p => p.status === 'fail').length,
        tests: tests.map((_, i) => ({ status: prog.find(x => x.test_idx === i)?.status || null })),
      };
    });
  }

  return {
    project, vulns, targets,
    ports: groupBy(ports, 'target_id'),
    endpoints: groupBy(endpoints, 'target_id'),
    wstgProgress: Object.fromEntries(wstg.map(r => [r.test_id, r])),
    methodProgress,
  };
}

// The route's entry point. rptData is the browser's report snapshot (same as
// the PDF gets); without one, the server copy of the report is used.
async function exportProjectDocx(projectId, { rptData, type, scope } = {}) {
  const loaded = await loadReportData(projectId);
  let report = parseReport(rptData);
  if (!rptData || !Object.keys(report).length) {
    const { rows } = await db.query('SELECT data FROM report_config WHERE project_id = $1', [projectId]);
    report = rows[0]?.data || {};
  }
  return generateDocx({ ...loaded, report, type, scope });
}

module.exports = { generateDocx, loadReportData, exportProjectDocx, normalizeReport, sectionIncluded };
