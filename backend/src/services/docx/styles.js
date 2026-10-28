// Named Word styles for the DOCX report.
//
// The whole word/styles.xml is written here and handed to Packer as an
// override, so every paragraph, character and table style the document uses
// is a real, named style the reader can restyle once in Word ("Título 1"
// changes every section heading). docx's own style API cannot declare table
// styles and keeps its default heading definitions around, which would give
// duplicate style ids; owning the file avoids both.
//
// Fonts are Calibri + Consolas only: they ship with Office, Inter does not.

const FONT      = 'Calibri';
const MONO      = 'Consolas';
const INK       = '111827';   // headings
const TEXT      = '374151';   // body text (dark grey)
const MUTED     = '6B7280';
const RULE      = 'E5E7EB';
const HEAD_FILL = 'F3F4F6';

// Content width of an A4 page with 2.5 cm margins, in twips.
const PAGE_W   = 11906;
const PAGE_H   = 16838;
const MARGIN   = 1417;
const CONTENT_W = PAGE_W - 2 * MARGIN;   // 9072

const xmlEsc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function rFonts(f) {
  return `<w:rFonts w:ascii="${f}" w:hAnsi="${f}" w:cs="${f}" w:eastAsia="${f}"/>`;
}

// One <w:style>. p = pPr inner xml, r = rPr inner xml, extra = anything else
// (tblPr, link, ...). Order inside w:style follows the schema.
function style({ type = 'paragraph', id, name, basedOn, next, link, p = '', r = '', tbl = '', tc = '', isDefault, qFormat = true, uiPriority }) {
  return `<w:style w:type="${type}" w:styleId="${id}"${isDefault ? ' w:default="1"' : ''}>`
    + `<w:name w:val="${xmlEsc(name)}"/>`
    + (basedOn ? `<w:basedOn w:val="${basedOn}"/>` : '')
    + (next ? `<w:next w:val="${next}"/>` : '')
    + (link ? `<w:link w:val="${link}"/>` : '')
    + (uiPriority != null ? `<w:uiPriority w:val="${uiPriority}"/>` : '')
    + (qFormat ? '<w:qFormat/>' : '')
    + (p ? `<w:pPr>${p}</w:pPr>` : '')
    + (r ? `<w:rPr>${r}</w:rPr>` : '')
    + (tbl ? `<w:tblPr>${tbl}</w:tblPr>` : '')
    + (tc ? `<w:tcPr>${tc}</w:tcPr>` : '')
    + '</w:style>';
}

const border = (side, color, sz = 4, space = 0, val = 'single') =>
  `<w:${side} w:val="${val}" w:sz="${sz}" w:space="${space}" w:color="${color}"/>`;

function tableBorders(color, { left, insideV = true, insideH = true, leftSz = 4 } = {}) {
  return '<w:tblBorders>'
    + border('top', color) + border('left', left || color, leftSz) + border('bottom', color) + border('right', color)
    + (insideH ? border('insideH', color) : '<w:insideH w:val="nil"/>')
    + (insideV ? border('insideV', color) : '<w:insideV w:val="nil"/>')
    + '</w:tblBorders>';
}

const cellMargins = (tb, lr) =>
  `<w:tblCellMar><w:top w:w="${tb}" w:type="dxa"/><w:left w:w="${lr}" w:type="dxa"/><w:bottom w:w="${tb}" w:type="dxa"/><w:right w:w="${lr}" w:type="dxa"/></w:tblCellMar>`;

function buildStylesXml({ accent }) {
  const A = accent;
  const s = [];

  // ── Paragraph styles ───────────────────────────────────────────────
  s.push(style({ id: 'Normal', name: 'Normal', isDefault: true,
    p: '<w:spacing w:after="120" w:line="276" w:lineRule="auto"/><w:jc w:val="both"/>',
    r: `${rFonts(FONT)}<w:color w:val="${TEXT}"/><w:sz w:val="21"/><w:szCs w:val="21"/>` }));

  // Section heading: uppercase, letter-spaced, accent left border, thin rule
  // under it. outlineLvl drives the TOC field.
  s.push(style({ id: 'Heading1', name: 'Título 1', basedOn: 'Normal', next: 'Normal', uiPriority: 9,
    p: '<w:keepNext/><w:keepLines/>'
      + `<w:pBdr>${border('left', A, 24, 8)}${border('bottom', RULE, 4, 4)}</w:pBdr>`
      + '<w:spacing w:before="360" w:after="160"/><w:ind w:left="170"/><w:jc w:val="left"/><w:outlineLvl w:val="0"/>',
    r: `<w:b/><w:bCs/><w:caps/><w:color w:val="${INK}"/><w:spacing w:val="30"/><w:sz w:val="24"/><w:szCs w:val="24"/>` }));
  s.push(style({ id: 'Heading2', name: 'Título 2', basedOn: 'Normal', next: 'Normal', uiPriority: 9,
    p: '<w:keepNext/><w:keepLines/>'
      + `<w:pBdr>${border('left', A, 12, 8)}${border('bottom', RULE, 2, 3)}</w:pBdr>`
      + '<w:spacing w:before="280" w:after="120"/><w:ind w:left="170"/><w:jc w:val="left"/><w:outlineLvl w:val="1"/>',
    r: `<w:b/><w:bCs/><w:caps/><w:color w:val="4B5563"/><w:spacing w:val="20"/><w:sz w:val="19"/><w:szCs w:val="19"/>` }));
  s.push(style({ id: 'Heading3', name: 'Título 3', basedOn: 'Normal', next: 'Normal', uiPriority: 9,
    p: '<w:keepNext/><w:keepLines/><w:spacing w:before="240" w:after="100"/><w:jc w:val="left"/><w:outlineLvl w:val="2"/>',
    r: `<w:b/><w:bCs/><w:color w:val="${INK}"/><w:sz w:val="22"/><w:szCs w:val="22"/>` }));
  s.push(style({ id: 'Heading4', name: 'Título 4', basedOn: 'Normal', next: 'Normal', uiPriority: 9,
    p: '<w:keepNext/><w:spacing w:before="180" w:after="80"/><w:jc w:val="left"/><w:outlineLvl w:val="3"/>',
    r: `<w:b/><w:bCs/><w:color w:val="${INK}"/><w:sz w:val="21"/><w:szCs w:val="21"/>` }));

  s.push(style({ id: 'ListBullet', name: 'Lista con viñetas', basedOn: 'Normal',
    p: '<w:spacing w:after="60"/>' }));
  s.push(style({ id: 'ListNumber', name: 'Lista numerada', basedOn: 'Normal',
    p: '<w:spacing w:after="60"/>' }));
  s.push(style({ id: 'ListParagraph', name: 'List Paragraph', basedOn: 'Normal', qFormat: false,
    p: '<w:ind w:left="720"/>' }));

  // Code: dark block for evidence / terminal output and payloads.
  s.push(style({ id: 'Codigo', name: 'Código', basedOn: 'Normal',
    p: `<w:pBdr>${['top', 'left', 'bottom', 'right'].map(sd => border(sd, '1F2937', 4, 4)).join('')}</w:pBdr>`
      + '<w:shd w:val="clear" w:color="auto" w:fill="1F2937"/>'
      + '<w:spacing w:before="60" w:after="120" w:line="240" w:lineRule="auto"/><w:ind w:left="113" w:right="113"/><w:jc w:val="left"/>',
    r: `${rFonts(MONO)}<w:color w:val="E5E7EB"/><w:sz w:val="16"/><w:szCs w:val="16"/>` }));
  // Light variant for HTTP request/response proofs (as the PDF draws them).
  s.push(style({ id: 'CodigoHTTP', name: 'Código HTTP', basedOn: 'Codigo',
    p: `<w:pBdr>${['top', 'left', 'bottom', 'right'].map(sd => border(sd, RULE, 4, 4)).join('')}</w:pBdr>`
      + '<w:shd w:val="clear" w:color="auto" w:fill="F9FAFB"/>',
    r: `<w:color w:val="1F2937"/>` }));

  s.push(style({ id: 'Cita', name: 'Cita', basedOn: 'Normal', next: 'Normal',
    p: `<w:pBdr>${border('left', A, 12, 8)}</w:pBdr><w:ind w:left="284"/>`,
    r: `<w:i/><w:iCs/><w:color w:val="4B5563"/>` }));

  s.push(style({ id: 'TablaTexto', name: 'Texto de tabla', basedOn: 'Normal',
    p: '<w:spacing w:after="0" w:line="252" w:lineRule="auto"/><w:jc w:val="left"/>',
    r: '<w:sz w:val="19"/><w:szCs w:val="19"/>' }));
  s.push(style({ id: 'TablaCabecera', name: 'Cabecera de tabla', basedOn: 'TablaTexto',
    p: '<w:keepNext/>',
    r: `${rFonts(MONO)}<w:b/><w:bCs/><w:caps/><w:color w:val="4B5563"/><w:spacing w:val="10"/><w:sz w:val="15"/><w:szCs w:val="15"/>` }));

  s.push(style({ id: 'EtiquetaCampo', name: 'Etiqueta de campo', basedOn: 'Normal', next: 'Normal',
    p: '<w:keepNext/><w:spacing w:before="160" w:after="60"/><w:jc w:val="left"/>',
    r: `${rFonts(MONO)}<w:b/><w:bCs/><w:caps/><w:color w:val="${MUTED}"/><w:spacing w:val="16"/><w:sz w:val="15"/><w:szCs w:val="15"/>` }));
  s.push(style({ id: 'HallazgoTitulo', name: 'Título de hallazgo', basedOn: 'Normal', next: 'HallazgoMeta',
    p: '<w:keepNext/><w:spacing w:after="40"/><w:jc w:val="left"/>',
    r: `<w:b/><w:bCs/><w:color w:val="${INK}"/><w:sz w:val="22"/><w:szCs w:val="22"/>` }));
  s.push(style({ id: 'HallazgoMeta', name: 'Datos de hallazgo', basedOn: 'Normal',
    p: '<w:spacing w:after="0"/><w:jc w:val="left"/>',
    r: `${rFonts(MONO)}<w:color w:val="${MUTED}"/><w:sz w:val="15"/><w:szCs w:val="15"/>` }));
  s.push(style({ id: 'GrupoSeveridad', name: 'Grupo de severidad', basedOn: 'Normal', next: 'Normal',
    p: `<w:keepNext/><w:pBdr>${border('bottom', RULE, 4, 4)}</w:pBdr><w:spacing w:before="320" w:after="160"/><w:jc w:val="left"/>`,
    r: `${rFonts(MONO)}<w:color w:val="${MUTED}"/><w:sz w:val="16"/><w:szCs w:val="16"/>` }));
  s.push(style({ id: 'Nota', name: 'Nota', basedOn: 'Normal',
    r: `<w:i/><w:iCs/><w:color w:val="${MUTED}"/><w:sz w:val="19"/><w:szCs w:val="19"/>` }));
  s.push(style({ id: 'Imagen', name: 'Imagen', basedOn: 'Normal',
    p: '<w:keepLines/><w:spacing w:before="60" w:after="120"/><w:jc w:val="center"/>' }));

  // Cover
  s.push(style({ id: 'PortadaTipo', name: 'Portada tipo', basedOn: 'Normal',
    p: '<w:spacing w:before="480" w:after="200"/><w:jc w:val="center"/>',
    r: `${rFonts(MONO)}<w:b/><w:caps/><w:color w:val="${A}"/><w:spacing w:val="40"/><w:sz w:val="17"/><w:szCs w:val="17"/>` }));
  s.push(style({ id: 'PortadaTitulo', name: 'Portada título', basedOn: 'Normal',
    p: '<w:spacing w:after="160"/><w:jc w:val="center"/>',
    r: `<w:b/><w:bCs/><w:color w:val="${INK}"/><w:sz w:val="56"/><w:szCs w:val="56"/>` }));
  s.push(style({ id: 'PortadaCliente', name: 'Portada cliente', basedOn: 'Normal',
    p: '<w:spacing w:after="160"/><w:jc w:val="center"/>',
    r: '<w:color w:val="4B5563"/><w:sz w:val="30"/><w:szCs w:val="30"/>' }));
  s.push(style({ id: 'PortadaClasificacion', name: 'Portada clasificación', basedOn: 'Normal',
    p: '<w:spacing w:before="200" w:after="0"/><w:jc w:val="center"/>',
    r: `${rFonts(MONO)}<w:b/><w:caps/><w:color w:val="B91C1C"/><w:spacing w:val="30"/><w:sz w:val="17"/><w:szCs w:val="17"/>` }));
  s.push(style({ id: 'PortadaEtiqueta', name: 'Portada etiqueta', basedOn: 'TablaTexto',
    r: `${rFonts(MONO)}<w:caps/><w:color w:val="${MUTED}"/><w:spacing w:val="16"/><w:sz w:val="14"/><w:szCs w:val="14"/>` }));
  s.push(style({ id: 'PortadaValor', name: 'Portada valor', basedOn: 'TablaTexto',
    r: `<w:color w:val="${INK}"/><w:sz w:val="19"/><w:szCs w:val="19"/>` }));

  // TOC
  s.push(style({ id: 'TOCHeading', name: 'TOC Heading', basedOn: 'Normal', next: 'Normal', uiPriority: 39,
    p: '<w:spacing w:before="0" w:after="200"/><w:jc w:val="left"/>',
    r: `${rFonts(MONO)}<w:b/><w:caps/><w:color w:val="${MUTED}"/><w:spacing w:val="30"/><w:sz w:val="17"/><w:szCs w:val="17"/>` }));
  s.push(style({ id: 'TOC1', name: 'toc 1', basedOn: 'Normal', next: 'Normal', uiPriority: 39,
    p: `<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="${CONTENT_W}"/></w:tabs><w:spacing w:before="40" w:after="40"/><w:jc w:val="left"/>`,
    r: `<w:color w:val="${INK}"/><w:sz w:val="20"/><w:szCs w:val="20"/>` }));
  s.push(style({ id: 'TOC2', name: 'toc 2', basedOn: 'Normal', next: 'Normal', uiPriority: 39,
    p: `<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="${CONTENT_W}"/></w:tabs><w:spacing w:after="20"/><w:ind w:left="340"/><w:jc w:val="left"/>`,
    r: '<w:color w:val="4B5563"/><w:sz w:val="18"/><w:szCs w:val="18"/>' }));

  // Header / footer
  s.push(style({ id: 'Header', name: 'header', basedOn: 'Normal', qFormat: false,
    p: '<w:spacing w:after="0"/><w:jc w:val="left"/>',
    r: `<w:color w:val="555555"/><w:sz w:val="16"/><w:szCs w:val="16"/>` }));
  s.push(style({ id: 'Footer', name: 'footer', basedOn: 'Normal', qFormat: false,
    p: '<w:spacing w:after="0"/><w:jc w:val="left"/>',
    r: `${rFonts(MONO)}<w:color w:val="555555"/><w:sz w:val="14"/><w:szCs w:val="14"/>` }));

  // ── Character styles ───────────────────────────────────────────────
  s.push(style({ type: 'character', id: 'DefaultParagraphFont', name: 'Default Paragraph Font', isDefault: true, qFormat: false, uiPriority: 1 }));
  s.push(style({ type: 'character', id: 'CodigoCar', name: 'Código en línea', basedOn: 'DefaultParagraphFont',
    r: `${rFonts(MONO)}<w:color w:val="1F2937"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:shd w:val="clear" w:color="auto" w:fill="${HEAD_FILL}"/>` }));
  s.push(style({ type: 'character', id: 'EtiquetaSeveridad', name: 'Etiqueta severidad', basedOn: 'DefaultParagraphFont',
    r: `${rFonts(MONO)}<w:b/><w:bCs/><w:caps/><w:spacing w:val="10"/><w:sz w:val="15"/><w:szCs w:val="15"/>` }));
  s.push(style({ type: 'character', id: 'CodigoHallazgo', name: 'Código de hallazgo', basedOn: 'DefaultParagraphFont',
    r: `${rFonts(MONO)}<w:b/><w:bCs/><w:color w:val="${MUTED}"/><w:sz w:val="17"/><w:szCs w:val="17"/>` }));
  s.push(style({ type: 'character', id: 'NumeroLinea', name: 'Número de línea', basedOn: 'DefaultParagraphFont',
    r: '<w:color w:val="9CA3AF"/>' }));
  s.push(style({ type: 'character', id: 'Hyperlink', name: 'Hyperlink', basedOn: 'DefaultParagraphFont', uiPriority: 99, qFormat: false,
    r: `<w:color w:val="${A}"/><w:u w:val="single"/>` }));

  // ── Table styles ───────────────────────────────────────────────────
  s.push(style({ type: 'table', id: 'TableNormal', name: 'Normal Table', isDefault: true, qFormat: false, uiPriority: 99,
    tbl: '<w:tblInd w:w="0" w:type="dxa"/>' + cellMargins(0, 108) }));
  s.push(style({ type: 'table', id: 'TablaResility', name: 'Tabla Resility', basedOn: 'TableNormal',
    p: '<w:spacing w:after="0"/><w:jc w:val="left"/>',
    tbl: tableBorders(RULE) + cellMargins(70, 110) }));
  s.push(style({ type: 'table', id: 'TablaHallazgo', name: 'Tabla Hallazgo', basedOn: 'TableNormal',
    tbl: tableBorders(RULE, { left: '9CA3AF', leftSz: 24, insideH: false, insideV: false }) + cellMargins(60, 200) }));
  s.push(style({ type: 'table', id: 'TablaConteo', name: 'Tabla Conteo', basedOn: 'TableNormal',
    p: '<w:spacing w:after="0"/><w:jc w:val="left"/>',
    tbl: tableBorders('FFFFFF', { leftSz: 12 }) + cellMargins(80, 140) }));
  s.push(style({ type: 'table', id: 'TablaSinBordes', name: 'Tabla sin bordes', basedOn: 'TableNormal',
    p: '<w:spacing w:after="0"/>',
    tbl: cellMargins(0, 60) }));

  return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    + '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    + ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    + '<w:docDefaults>'
    + `<w:rPrDefault><w:rPr>${rFonts(FONT)}<w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="es-ES" w:eastAsia="es-ES" w:bidi="ar-SA"/></w:rPr></w:rPrDefault>`
    + '<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault>'
    + '</w:docDefaults>'
    + s.join('')
    + '</w:styles>';
}

// Real Word numbering: bullets for <ul>/markdown lists, decimal for <ol>.
// Each <ol> gets its own `instance` so numbering restarts per list.
function numberingConfig() {
  const BULLETS = ['•', '◦', '▪', '•', '◦', '▪'];
  const ORDER   = ['decimal', 'lowerLetter', 'lowerRoman', 'decimal', 'lowerLetter', 'lowerRoman'];
  const indent  = l => ({ left: 360 + l * 340, hanging: 240 });
  return {
    config: [
      { reference: 'bullets', levels: BULLETS.map((text, level) => ({
        level, format: 'bullet', text, alignment: 'left',
        style: { paragraph: { indent: indent(level) } },
      })) },
      { reference: 'ordered', levels: ORDER.map((format, level) => ({
        level, format, text: `%${level + 1}.`, alignment: 'left',
        style: { paragraph: { indent: indent(level) } },
      })) },
    ],
  };
}

module.exports = {
  buildStylesXml, numberingConfig,
  FONT, MONO, INK, TEXT, MUTED, RULE, HEAD_FILL,
  PAGE_W, PAGE_H, MARGIN, CONTENT_W,
};
