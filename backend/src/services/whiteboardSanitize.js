// Sanitizer for the whiteboard blob saved by PUT /whiteboard. Any project
// writer can send it and every member's browser renders it, so only known
// fields survive: colors go through the same allowlists the MCP tools use,
// numbers are coerced to finite values and strings are capped. Invalid values
// fall back to a default instead of rejecting the whole save.
const {
  NOTE_COLORS, CARD_COLORS, EDGE_COLORS, EDGE_STYLES, EDGE_ARROWS, REF_TYPES, MAX_BOARD_ITEMS, MAX_ITEM_SIZE,
} = require('./mcp/whiteboard');
const { MAX_PROJECT_IMAGES } = require('./whiteboardImages');

const MAX_STROKES = 5000;
const MAX_PATH_LEN = 200000;
const ID_RE = /^[\w-]{1,100}$/;
const SAFE_COLOR_RE = /^(#[0-9a-f]{3,8}|var\(--[a-z0-9-]+\))$/i;
const SAFE_PATH_RE = /^[MLHVCSQTAZmlhvcsqtaz0-9.,eE+\- ]*$/;
const DEFAULT_STROKE_COLOR = '#e94141';
// Bounds for an item's optional w/h. The browser enforces tighter per-type
// minimums while resizing; this only keeps a hand-crafted blob from producing
// zero-size or absurdly large boxes.
const MIN_ITEM_SIZE = 60;

class WhiteboardDataError extends Error {}

const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const num = (v, fallback) => (typeof v === 'number' && Number.isFinite(v) ? v : fallback);
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : undefined);
const validId = v => typeof v === 'string' && ID_RE.test(v);
const size = v => (typeof v === 'number' && Number.isFinite(v)
  ? Math.min(MAX_ITEM_SIZE, Math.max(MIN_ITEM_SIZE, v))
  : undefined);

// Copies optional fields only when present and valid, so a legit payload
// round-trips without gaining keys it did not have.
function setIf(out, key, value) {
  if (value !== undefined) out[key] = value;
}

function position(item) {
  const out = { id: item.id, x: num(item.x, 0), y: num(item.y, 0) };
  setIf(out, 'w', size(item.w));
  setIf(out, 'h', size(item.h));
  return out;
}

function sanitizeNode(n) {
  const out = position(n);
  if (n.collapsed !== undefined) out.collapsed = Boolean(n.collapsed);
  setIf(out, 'created_by', str(n.created_by, 50));
  return out;
}

// What a card points at (REF_TYPES). The browser looks the id up in the
// project data it already has (a finding card shows the CURRENT finding from
// GET /vulns), so an unknown type is dropped with the whole ref and ids must
// look like ids.
function sanitizeRef(ref) {
  if (!isPlainObject(ref) || !REF_TYPES.includes(ref.type)) return undefined;
  const out = { type: ref.type };
  for (const key of ['id', 'target_id']) {
    if (ref[key] === null) out[key] = null;
    else if (validId(ref[key])) out[key] = ref[key];
  }
  if (ref.label === null) out.label = null;
  else setIf(out, 'label', str(ref.label, 1000));
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
  const out = position(n);
  setIf(out, 'text', str(n.text, 20000));
  out.color = NOTE_COLORS.includes(n.color) ? n.color : NOTE_COLORS[0];
  setIf(out, 'created_by', str(n.created_by, 50));
  return out;
}

// Imagen: solo el id de su fila en whiteboard_images (los bytes nunca van
// en el blob). Sin imageId válido el ítem no sirve y se descarta.
function sanitizeImage(i) {
  if (!validId(i.imageId)) return null;
  const out = position(i);
  out.imageId = i.imageId;
  setIf(out, 'caption', str(i.caption, 500));
  setIf(out, 'created_by', str(i.created_by, 50));
  return out;
}

function sanitizeEdge(e) {
  if (!validId(e.fromId) || !validId(e.toId)) return null;
  const out = { id: e.id, fromId: e.fromId, toId: e.toId };
  // Optional endpoint/port of a target node each end points at.
  for (const key of ['fromEp', 'toEp', 'fromPort', 'toPort']) {
    if (validId(e[key])) out[key] = e[key];
  }
  setIf(out, 'label', str(e.label, 500));
  // Style fields have no default worth storing: an invalid value is dropped
  // and the browser draws the default (solid, arrow at the end, theme color).
  if (EDGE_STYLES.includes(e.style)) out.style = e.style;
  if (EDGE_ARROWS.includes(e.arrow)) out.arrow = e.arrow;
  if (EDGE_COLORS.includes(e.color)) out.color = e.color;
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
  images:  { fn: sanitizeImage,  max: MAX_PROJECT_IMAGES },
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
  // Only a request flag ("targets were auto-placed"): mergeBoard keeps it in
  // whiteboard_state.sync, never in the stored blob.
  if (data.initialized === true) out.initialized = true;
  return out;
}

// Sync fields of PUT /whiteboard next to `data` (see services/whiteboardSync.js).
// base_revision: the board revision the client's copy is based on; without it
// the PUT is treated as a legacy full-board save (never deletes anything).
// removed: { kind: [ids] } the client deleted since that base.
function sanitizeSyncRequest(body) {
  const out = { baseRevision: undefined, removed: {} };
  const base = body?.base_revision;
  if (base !== undefined && base !== null) {
    if (!Number.isSafeInteger(base) || base < 0) throw new WhiteboardDataError('base_revision must be a non-negative integer');
    out.baseRevision = base;
  }
  const removed = body?.removed;
  if (removed === undefined || removed === null) return out;
  if (!isPlainObject(removed)) throw new WhiteboardDataError('removed must be an object of id lists');
  if (out.baseRevision === undefined) throw new WhiteboardDataError('removed requires base_revision');
  for (const [key, { max }] of Object.entries(LISTS)) {
    if (!Array.isArray(removed[key])) continue;
    out.removed[key] = [...new Set(removed[key].filter(validId))].slice(0, max);
  }
  return out;
}

const LIST_LIMITS = Object.fromEntries(Object.entries(LISTS).map(([key, { max }]) => [key, max]));

module.exports = { sanitizeWhiteboardData, sanitizeSyncRequest, LIST_LIMITS, WhiteboardDataError };
