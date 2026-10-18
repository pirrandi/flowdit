// Sanitizer for the whiteboard blob saved by PUT /whiteboard. Any project
// writer can send it and every member's browser renders it, so only known
// fields survive: colors go through the same allowlists the MCP tools use,
// numbers are coerced to finite values and strings are capped. Invalid values
// fall back to a default instead of rejecting the whole save.
const { NOTE_COLORS, CARD_COLORS, MAX_BOARD_ITEMS } = require('./mcp/whiteboard');

const MAX_STROKES = 5000;
const MAX_PATH_LEN = 200000;
const ID_RE = /^[\w-]{1,100}$/;
const SAFE_COLOR_RE = /^(#[0-9a-f]{3,8}|var\(--[a-z0-9-]+\))$/i;
const SAFE_PATH_RE = /^[MLHVCSQTAZmlhvcsqtaz0-9.,eE+\- ]*$/;
const DEFAULT_STROKE_COLOR = '#e94141';

class WhiteboardDataError extends Error {}

const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const num = (v, fallback) => (typeof v === 'number' && Number.isFinite(v) ? v : fallback);
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : undefined);
const validId = v => typeof v === 'string' && ID_RE.test(v);

// Copies optional fields only when present and valid, so a legit payload
// round-trips without gaining keys it did not have.
function setIf(out, key, value) {
  if (value !== undefined) out[key] = value;
}

function position(item) {
  const out = { id: item.id, x: num(item.x, 0), y: num(item.y, 0) };
  setIf(out, 'w', num(item.w, undefined));
  setIf(out, 'h', num(item.h, undefined));
  return out;
}

function sanitizeNode(n) {
  const out = position(n);
  if (n.collapsed !== undefined) out.collapsed = Boolean(n.collapsed);
  setIf(out, 'created_by', str(n.created_by, 50));
  return out;
}

function sanitizeRef(ref) {
  if (!isPlainObject(ref)) return undefined;
  const out = {};
  for (const [key, max] of [['type', 20], ['id', 100], ['target_id', 100], ['label', 1000]]) {
    if (ref[key] === null) out[key] = null;
    else setIf(out, key, str(ref[key], max));
  }
  return out;
}

function sanitizeCard(c) {
  const out = position(c);
  setIf(out, 'title', str(c.title, 500));
  setIf(out, 'body', str(c.body, 50000));
  out.color = CARD_COLORS.includes(c.color) ? c.color : CARD_COLORS[0];
  setIf(out, 'ref', sanitizeRef(c.ref));
  setIf(out, 'created_by', str(c.created_by, 50));
  return out;
}

function sanitizeNote(n) {
  const out = { id: n.id, x: num(n.x, 0), y: num(n.y, 0) };
  setIf(out, 'text', str(n.text, 20000));
  out.color = NOTE_COLORS.includes(n.color) ? n.color : NOTE_COLORS[0];
  setIf(out, 'created_by', str(n.created_by, 50));
  return out;
}

function sanitizeEdge(e) {
  if (!validId(e.fromId) || !validId(e.toId)) return null;
  const out = { id: e.id, fromId: e.fromId, toId: e.toId };
  setIf(out, 'label', str(e.label, 500));
  setIf(out, 'created_by', str(e.created_by, 50));
  return out;
}

function sanitizeStroke(s) {
  if (typeof s.d !== 'string' || s.d.length > MAX_PATH_LEN || !SAFE_PATH_RE.test(s.d)) return null;
  const width = num(s.width, 2);
  return {
    id: s.id,
    d: s.d,
    color: typeof s.color === 'string' && SAFE_COLOR_RE.test(s.color) ? s.color : DEFAULT_STROKE_COLOR,
    width: width > 0 ? width : 2,
  };
}

const LISTS = {
  nodes:   { fn: sanitizeNode,   max: MAX_BOARD_ITEMS },
  cards:   { fn: sanitizeCard,   max: MAX_BOARD_ITEMS },
  notes:   { fn: sanitizeNote,   max: MAX_BOARD_ITEMS },
  edges:   { fn: sanitizeEdge,   max: MAX_BOARD_ITEMS },
  strokes: { fn: sanitizeStroke, max: MAX_STROKES },
};

function sanitizeWhiteboardData(data) {
  if (!isPlainObject(data)) throw new WhiteboardDataError('data must be an object');
  const out = {};
  for (const [key, { fn, max }] of Object.entries(LISTS)) {
    if (!Array.isArray(data[key])) continue;
    out[key] = data[key]
      .filter(item => isPlainObject(item) && validId(item.id))
      .map(fn)
      .filter(Boolean)
      .slice(0, max);
  }
  if (isPlainObject(data.view)) {
    const zoom = num(data.view.zoom, 1);
    out.view = { panX: num(data.view.panX, 0), panY: num(data.view.panY, 0), zoom: zoom > 0 ? zoom : 1 };
  }
  return out;
}

module.exports = { sanitizeWhiteboardData, WhiteboardDataError };
