// Report sections for Claude Code (get_report_sections / propose_report_section).
// The report builder (frontend/export.html) stores its whole state as one
// JSONB blob in report_config. Claude Code never writes that blob: it only
// PROPOSES the HTML of one prose field, and the field is written when a lead
// approves the proposal (approveProposal in proposals.js).
//
// Editable targets, and nothing else:
//   - a custom section's `content` (type 'custom'),
//   - the `content` of a custom section's subsection (children[]),
//   - the executive summary's `description` (the intro text above the
//     generated severity table).
// Every other built-in section is generated from project data (findings,
// WSTG, targets...), so prose written there would never reach the report.
const { parse } = require('node-html-parser');

// Same guard as PUT /report-config: the blob is text + layout, never binary.
const REPORT_MAX_BYTES = 2 * 1024 * 1024;
// One proposal is one section's prose: generous for a long section, small
// enough that a runaway model cannot fill the blob with a single field.
const MAX_CONTENT_CHARS = 50000;
const MAX_RATIONALE_CHARS = 2000;
const EXEC_SUMMARY = 'exec-summary';

// ── HTML sanitizer ─────────────────────────────────────────────────────
// Strict allowlist for report prose. The report builder injects this HTML
// as-is into the preview, the PDF render and every lead's browser, so the
// output is REBUILT from the parse tree, never passed through: only these
// tags survive, every text node is re-escaped, and the only attribute kept
// is an http(s)/mailto href. A parser quirk can therefore only change the
// structure of the result, never smuggle markup into it.
const ALLOWED_TAGS = new Set([
  'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'ul', 'ol', 'li', 'h3', 'h4',
  'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption',
  'code', 'pre', 'blockquote', 'a',
]);
// Dropped together with their content. Any other unknown tag is unwrapped
// (its text is kept, the tag is not).
const DROP_WITH_CONTENT = new Set([
  'script', 'style', 'noscript', 'template', 'iframe', 'object', 'embed', 'frame', 'frameset',
  'svg', 'math', 'textarea', 'select', 'option', 'title', 'head', 'button', 'form', 'input',
]);
const VOID_TAGS = new Set(['br']);
const SAFE_HREF_RE = /^(https?:\/\/|mailto:)/i;

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function safeHref(value) {
  // Browsers ignore whitespace/control characters inside the scheme
  // ("java\tscript:"), so they are stripped before the check.
  // eslint-disable-next-line no-control-regex
  const href = String(value || '').replace(/[\x00-\x20\x7f-\x9f]/g, '');
  return SAFE_HREF_RE.test(href) ? href : null;
}

function serialize(node) {
  let out = '';
  for (const child of node.childNodes) {
    if (child.nodeType === 3) { out += escapeHtml(child.text); continue; }
    if (child.nodeType !== 1) continue; // comments
    const tag = (child.rawTagName || '').toLowerCase();
    if (DROP_WITH_CONTENT.has(tag)) continue;
    if (!ALLOWED_TAGS.has(tag)) { out += serialize(child); continue; }
    let attrs = '';
    if (tag === 'a') {
      const href = safeHref(child.getAttribute('href'));
      if (!href) { out += serialize(child); continue; } // a link without a safe target is just text
      attrs = ` href="${escapeHtml(href)}" rel="noopener noreferrer"`;
    }
    out += VOID_TAGS.has(tag) ? `<${tag}>` : `<${tag}${attrs}>${serialize(child)}</${tag}>`;
  }
  return out;
}

function sanitizeReportHtml(html) {
  // script/style are kept as raw text so their body never becomes elements
  // (they are dropped whole anyway); <pre> is parsed so <code> inside it works.
  const root = parse(String(html || ''), { blockTextElements: { script: true, noscript: true, style: true } });
  const out = serialize(root).trim();
  // Plain text with no tags would be read as markdown by the report builder
  // (_secContentHtml): wrap it so it stays prose.
  return out && !/<[a-z]/i.test(out) ? `<p>${out}</p>` : out;
}

// True when the sanitized HTML has no visible text left.
function isBlankHtml(html) {
  return !parse(html).text.trim();
}

// ── Locating a target inside report_config.data ───────────────────────
function sectionsOf(data) {
  return data && Array.isArray(data.sections) ? data.sections.filter(s => s && typeof s === 'object') : [];
}

function isEditableSection(section) {
  return section.type === 'custom' || section.id === EXEC_SUMMARY;
}

// Resolves section_id (+ subsection_id) to the object that holds the field
// and the field name. Returns { error } for anything that cannot be written:
// unknown ids and built-in sections are refused here, before a proposal
// exists, and again at approval time (the section may be gone by then).
function locateTarget(data, sectionId, subsectionId) {
  const section = sectionsOf(data).find(s => s.id === sectionId);
  if (!section) return { error: `section_id "${sectionId}" does not exist in this report — call get_report_sections` };
  const sectionTitle = typeof section.title === 'string' ? section.title : section.id;
  if (!isEditableSection(section)) {
    return { error: `section "${sectionTitle}" (${section.type}) is generated from project data and cannot be written — only custom sections, their subsections and the executive summary are editable` };
  }
  if (subsectionId) {
    if (section.type !== 'custom') return { error: `section "${sectionTitle}" has no editable subsections` };
    const child = (Array.isArray(section.children) ? section.children : []).find(c => c && c.id === subsectionId);
    if (!child) return { error: `subsection_id "${subsectionId}" does not exist in section "${sectionTitle}" — call get_report_sections` };
    return {
      holder: child, field: 'content', sectionTitle,
      subsectionTitle: typeof child.title === 'string' ? child.title : child.id,
      current: typeof child.content === 'string' ? child.content : '',
    };
  }
  const field = section.id === EXEC_SUMMARY ? 'description' : 'content';
  return {
    holder: section, field, sectionTitle, subsectionTitle: null,
    current: typeof section[field] === 'string' ? section[field] : '',
  };
}

function clip(s, max) {
  if (typeof s !== 'string') return s ?? null;
  return s.length > max ? `${s.slice(0, max)}… [truncated ${s.length - max} chars]` : s;
}

// Compact view of the report for get_report_sections.
function describeSections(data) {
  return sectionsOf(data).map(s => {
    const editable = isEditableSection(s);
    const field = s.id === EXEC_SUMMARY ? 'description' : 'content';
    return {
      id: s.id, type: s.type || null, title: s.title || null, visible: s.visible !== false, editable,
      field: editable ? field : null,
      content: clip(typeof s[field] === 'string' ? s[field] : (typeof s.description === 'string' ? s.description : null), 20000),
      children: (Array.isArray(s.children) ? s.children : []).filter(c => c && typeof c === 'object').map(c => ({
        id: c.id, title: c.title || null, visible: c.visible !== false, editable: s.type === 'custom',
        content: clip(typeof c.content === 'string' ? c.content : null, 20000),
      })),
    };
  });
}

module.exports = {
  sanitizeReportHtml, isBlankHtml, locateTarget, describeSections, sectionsOf,
  REPORT_MAX_BYTES, MAX_CONTENT_CHARS, MAX_RATIONALE_CHARS,
};
