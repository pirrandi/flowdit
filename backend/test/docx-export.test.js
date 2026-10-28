const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const request = require('supertest');
const JSZip = require('jszip');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

// A small, valid RGBA PNG (w×h, one colour) — its exact bytes are what the
// DOCX media folder must end up holding.
function png(w, h, rgba = [200, 30, 30, 255]) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6;
  const row = Buffer.concat([Buffer.from([0]), Buffer.from(Array(w).fill(rgba).flat())]);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(Buffer.concat(Array(h).fill(row)))), chunk('IEND', Buffer.alloc(0)),
  ]);
}
const dataUrl = buf => `data:image/png;base64,${buf.toString('base64')}`;

const EVIDENCE = png(7, 5, [10, 120, 200, 255]);
const LOGO     = png(6, 2, [0, 0, 0, 255]);

async function seed() {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken, { name: 'Acme DOCX', target: 'https://acme.test' });
  const auth = { Authorization: `Bearer ${owner.accessToken}` };
  const add = body => request(app).post(`/api/projects/${project.id}/vulns`).set(auth).send(body);

  const crit = (await add({
    name: 'SQL injection in login', severity: 'critical', category: 'Injection', cwe: 'CWE-89',
    description: 'Original DB description that the report rewrite replaces.',
    remediation: 'Use **parameterised** queries.\n- bind every value\n- drop dynamic SQL',
    payloads: ["' OR 1=1 --"],
    evidence: [{ name: 'proof.png', data: dataUrl(EVIDENCE), phase: 'original' }],
  })).body;
  const med = (await add({ name: 'Verbose error pages', severity: 'medium', description: 'Stack traces leak.' })).body;
  await db.query(
    `UPDATE custom_vulns SET http_proofs = $2 WHERE id = $1`,
    [crit.id, JSON.stringify([{ method: 'POST', request: 'POST /login HTTP/1.1\nHost: acme.test', response: 'HTTP/1.1 500\n\nerror', annotation: 'Server crashed' }])]
  );
  return { owner, project, auth, crit, med };
}

function report({ crit, med }, overrides = {}) {
  const meta = {
    coverTitle: 'Informe Acme', classification: 'TLP:AMBER', preparedBy: 'Red Team', organization: 'Acme',
    showToc: true, numbering: true, accentColor: '#0891b2',
    coverFields: { date: true, preparedBy: true, organization: true },
    header: { enabled: true, cols: {
      left: { mode: 'image', img: dataUrl(LOGO), text: '' },
      center: { mode: 'text', text: '' },
      right: { mode: 'text', text: 'Header right text' },
    } },
    footer: { enabled: true, cols: {
      left: { mode: 'text', text: 'info@acme.test' },
      center: { mode: 'pagenum', text: 'Página' },
      right: { mode: 'text', text: 'www.acme.test' },
    } },
    watermark: { enabled: true, text: 'CONFIDENCIAL' },
    ...(overrides.meta || {}),
  };
  return {
    meta,
    sections: overrides.sections || [
      { id: 'custom-intro', type: 'custom', title: 'Introducción Acme', visible: true, pageBreak: true,
        content: '<p style="text-align:center"><strong>Bold</strong> intro</p><ul><li>uno<ul><li>anidado</li></ul></li></ul><table><tr><th>Col A</th><th>Col B</th></tr><tr><td>a1</td><td>b1</td></tr></table>',
        children: [{ id: 'sub-1', title: 'Subsección visible', content: '<p>sub body</p>', visible: true },
                   { id: 'sub-2', title: 'Subsección oculta', content: '<p>nope</p>', visible: false }] },
      { id: 'custom-hidden', type: 'custom', title: 'Sección Oculta Secreta', visible: false, content: '<p>hidden body</p>' },
      { id: 'exec-summary', type: 'exec-summary', title: 'Resumen Ejecutivo', visible: true },
      { id: 'findings-index', type: 'findings-index', title: 'Índice de Hallazgos', visible: true },
      { id: 'wstg', type: 'wstg', title: 'Cobertura OWASP WSTG', visible: false },
      { id: 'targets', type: 'targets', title: 'Alcance — Objetivos', visible: false },
      { id: 'detailed-findings', type: 'detailed-findings', title: 'Hallazgos Detallados', visible: true },
      { id: 'risk-matrix', type: 'risk-matrix', title: 'Matriz de Riesgo', visible: false },
      { id: 'remediation-roadmap', type: 'remediation-roadmap', title: 'Hoja de Ruta de Remediación', visible: false },
    ],
    vulnEdits: {
      [crit.id]: { description: '<p>Rewritten description from the report editor</p>', execAction: 'Patch the login query now', probability: 5 },
      [med.id]: { businessImpact: 'Information disclosure' },
    },
    ...(overrides.extra || {}),
  };
}

async function exportDocx(s, body) {
  const res = await request(app)
    .post('/api/export/docx')
    .set(s.auth)
    .buffer(true)
    .parse((r, cb) => { const parts = []; r.on('data', c => parts.push(c)); r.on('end', () => cb(null, Buffer.concat(parts))); })
    .send({ projectId: s.project.id, ...body });
  assert.equal(res.status, 200, String(res.body));
  const zip = await JSZip.loadAsync(res.body);
  const read = name => zip.file(name)?.async('string');
  const parts = Object.keys(zip.files);
  const xmlOf = async re => (await Promise.all(parts.filter(p => re.test(p)).map(p => read(p)))).join('\n');
  return { zip, parts, read, xmlOf, document: await read('word/document.xml'), styles: await read('word/styles.xml') };
}

// Visible text of document.xml (runs concatenated per paragraph).
const textOf = xml => xml.replace(/<w:p[ >]/g, '\n$&').replace(/<[^>]+>/g, '')
  .replace(/&apos;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

test('DOCX export carries the report content, named styles, header/footer, watermark and evidence', async () => {
  const s = await seed();
  const out = await exportDocx(s, { type: 'technical', rptData: JSON.stringify(report(s)) });
  const text = textOf(out.document);

  // vulnEdits override the DB description; DB remediation markdown still renders.
  assert.match(text, /Rewritten description from the report editor/);
  assert.doesNotMatch(text, /Original DB description/);
  assert.match(text, /parameterised/);

  // Sections, numbering, subsections; hidden ones are absent.
  for (const t of ['1. Introducción Acme', '1.1 Subsección visible', '2. Resumen Ejecutivo', '3. Índice de Hallazgos', '4. Hallazgos Detallados']) {
    assert.ok(text.includes(t), `missing "${t}"`);
  }
  assert.ok(!text.includes('Sección Oculta Secreta'));
  assert.ok(!text.includes('hidden body'));
  assert.ok(!text.includes('Subsección oculta'));
  // Technical type does not force the executive sections in.
  assert.ok(!text.includes('Matriz de Riesgo'));

  // Finding codes, payload, HTTP proof.
  assert.match(text, /C1/);
  assert.match(text, /M1/);
  assert.match(text, /' OR 1=1 --/);
  assert.match(text, /POST \/login HTTP\/1\.1/);

  // Headings are paragraph styles; HTML lists use real numbering; HTML tables
  // use the named table style.
  assert.match(out.document, /<w:pStyle w:val="Heading1"\/>/);
  assert.match(out.document, /<w:pStyle w:val="Heading2"\/>/);
  assert.match(out.document, /<w:numPr><w:ilvl w:val="1"\/>/);
  assert.match(out.document, /<w:tblStyle w:val="TablaResility"\/>/);
  assert.match(out.document, /<w:tblStyle w:val="TablaHallazgo"\/>/);

  // Real TOC field over the heading styles, plus the update-on-open setting.
  assert.match(out.document, /<w:instrText[^>]*>TOC [^<]*\\o &quot;1-2&quot;/);
  assert.match(await out.read('word/settings.xml'), /<w:updateFields w:val="true"\/>|<w:updateFields\/>/);

  // Named styles in styles.xml.
  for (const name of ['Título 1', 'Título 2', 'Normal', 'Lista con viñetas', 'Tabla Resility', 'Tabla Hallazgo', 'Código']) {
    assert.ok(out.styles.includes(`<w:name w:val="${name}"/>`), `style "${name}" not defined`);
  }
  assert.match(out.styles, /w:styleId="Heading1"[\s\S]*?<w:outlineLvl w:val="0"\/>/);
  assert.match(out.styles, /w:ascii="Calibri"/);
  assert.doesNotMatch(out.styles, /Inter/);

  // Evidence and header logo are embedded as real images (exact bytes).
  const media = out.parts.filter(p => p.startsWith('word/media/') && !out.zip.files[p].dir);
  const bufs = await Promise.all(media.map(p => out.zip.file(p).async('nodebuffer')));
  assert.ok(bufs.some(b => b.equals(EVIDENCE)), 'evidence image not embedded');
  assert.ok(bufs.some(b => b.equals(LOGO)), 'header logo not embedded');

  // Footer: text columns + PAGE / NUMPAGES fields.
  const footers = await out.xmlOf(/^word\/footer\d+\.xml$/);
  assert.match(footers, /info@acme\.test/);
  assert.match(footers, /PAGE/);
  assert.match(footers, /NUMPAGES/);

  // Watermark: floating picture behind the text, anchored in the header.
  const headers = await out.xmlOf(/^word\/header\d+\.xml$/);
  assert.match(headers, /Header right text/);
  assert.match(headers, /<wp:anchor[^>]*behindDoc="1"/);
  assert.ok(media.some(p => p.endsWith('.svg')), 'watermark SVG missing');

  // Cover on its own first page (title page) with its metadata.
  assert.match(out.document, /<w:titlePg\/>/);
  assert.match(text, /Informe Acme/);
  assert.match(text, /TLP:AMBER/);
});

test('DOCX export applies executive-type forcing and the executive layout', async () => {
  const s = await seed();
  const out = await exportDocx(s, { type: 'executive', rptData: JSON.stringify(report(s)) });
  const text = textOf(out.document);
  // Forced in although hidden in the outline.
  assert.match(text, /Matriz de Riesgo/);
  assert.match(text, /Hoja de Ruta de Remediación/);
  assert.match(text, /Patch the login query now/);
  assert.match(text, /Hallazgos por Valoración de Riesgo/);
  // Technical-only section left out; exec summary lists critical/high impact.
  assert.doesNotMatch(text, /Hallazgos Detallados/);
  assert.match(text, /Riesgo General/);
  assert.match(text, /Hallazgos Críticos y de Alto Riesgo/);
});

test('DOCX export falls back to the persisted reportType / reportScope and findingInclude', async () => {
  const s = await seed();
  const rpt = report(s, { meta: { reportType: 'executive', findingInclude: { desc: false } } });
  const out = await exportDocx(s, { rptData: JSON.stringify(rpt) });
  const text = textOf(out.document);
  assert.match(text, /Hoja de Ruta de Remediación/);
  assert.doesNotMatch(text, /Hallazgos Detallados/);

  // Scope "wstg" drops the finding sections.
  const wstg = await exportDocx(s, { type: 'technical', scope: 'wstg', rptData: JSON.stringify(report(s)) });
  const wt = textOf(wstg.document);
  assert.doesNotMatch(wt, /Resumen Ejecutivo/);
  assert.doesNotMatch(wt, /Hallazgos Detallados/);
  assert.match(wt, /Introducción Acme/);

  // findingInclude.desc = false hides the description field in the cards.
  const noDesc = await exportDocx(s, { type: 'technical', rptData: JSON.stringify(report(s, { meta: { findingInclude: { desc: false } } })) });
  assert.doesNotMatch(textOf(noDesc.document), /Rewritten description/);
});

test('DOCX export renders Free Edit markdown instead of the generated report', async () => {
  const s = await seed();
  const rpt = report(s, { extra: { freeEditMd: '# Libre\n\n## Sección libre\n\nTexto **libre**\n\n- punto' } });
  const out = await exportDocx(s, { type: 'technical', rptData: JSON.stringify(rpt) });
  const text = textOf(out.document);
  assert.match(text, /Sección libre/);
  assert.match(text, /punto/);
  assert.doesNotMatch(text, /Hallazgos Detallados/);
  assert.match(out.document, /<w:pStyle w:val="Heading1"\/>/);
});

test('DOCX export survives malformed HTML and unusable images', async () => {
  const s = await seed();
  const rpt = report(s, { sections: [
    { id: 'custom-bad', type: 'custom', title: 'Rota', visible: true,
      content: '<div><p>unclosed <b>bold <table><tr><td>cell<img src="data:image/png;base64,AAAA"><img src="https://evil.test/x.png"></div></p><<>>texto final' },
  ] });
  const out = await exportDocx(s, { type: 'technical', rptData: JSON.stringify(rpt) });
  const text = textOf(out.document);
  assert.match(text, /unclosed/);
  assert.match(text, /texto final/);
});
