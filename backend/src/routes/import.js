const express   = require('express');
const multer    = require('multer');
const { XMLParser } = require('fast-xml-parser');
const db        = require('../db');
const { requireAuth }                        = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');

const router = express.Router({ mergeParams: true });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

router.use(requireAuth, requireProjectAccess);

// ── Helpers ─────────────────────────────────────────────────────────────
function stripHtml(val) {
  if (val == null) return '';
  return String(val)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, ' ')
    .trim();
}

function extractHostname(raw) {
  const s = String(raw || '').trim();
  try { return new URL(s).hostname || s; } catch { return s; }
}

async function upsertTarget(projectId, host, userId, targetMap) {
  if (!host) return null;
  const key = host.toLowerCase();
  if (targetMap.has(key)) return { id: targetMap.get(key), created: false };
  const { rows } = await db.query(
    `INSERT INTO targets (project_id, host, type, scope, notes, added_by)
     VALUES ($1,$2,'domain','in','',$3) RETURNING id`,
    [projectId, host, userId]
  );
  const id = rows[0].id;
  targetMap.set(key, id);
  return { id, created: true };
}

async function insertVuln(projectId, userId, { name, category, severity, description, remediation, notes, targetId, httpProofs = [] }) {
  await db.query(
    `INSERT INTO custom_vulns
       (project_id, name, category, severity, description, remediation, notes,
        items, payloads, evidence, http_proofs, target_id, created_by, updated_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'[]','[]','[]',$8,$9,$10,$10)`,
    [projectId, name, category, severity, description, remediation, notes, JSON.stringify(httpProofs), targetId, userId]
  );
}

// ── Burp Suite parser ───────────────────────────────────────────────────
const BURP_SEV = { high:'high', medium:'medium', low:'low', information:'info', informational:'info', 'false positive':'info', info:'info' };

function decodeBurpField(field, isBase64) {
  if (field == null) return null;
  const raw = typeof field === 'object' ? (field['#text'] || '') : String(field);
  if (!raw.trim()) return null;
  if (isBase64) {
    try { return Buffer.from(raw.trim(), 'base64').toString('utf8'); } catch { return raw; }
  }
  return raw;
}

async function parseBurp(xml, projectId, userId, targetMap) {
  const parser = new XMLParser({
    ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => ['issue', 'requestresponse'].includes(n),
  });
  const root = parser.parse(xml)?.issues;
  if (!root) throw new Error('Invalid Burp XML — missing <issues> root');

  const issues = [].concat(root.issue || []);
  let imported = 0, targetsCreated = 0;

  for (const issue of issues) {
    const hostRaw = issue.host;
    const host    = hostRaw ? extractHostname(typeof hostRaw === 'object' ? (hostRaw['#text'] || hostRaw['@_ip'] || '') : hostRaw) : null;
    const target  = await upsertTarget(projectId, host, userId, targetMap);
    if (target?.created) targetsCreated++;

    // Extract request/response pairs
    const httpProofs = [].concat(issue.requestresponse || []).map(rr => {
      const reqField  = rr.request;
      const respField = rr.response;
      const reqB64    = reqField?.['@_base64'] === 'true';
      const respB64   = respField?.['@_base64'] === 'true';
      const method    = reqField?.['@_method'] || null;
      const request   = decodeBurpField(reqField, reqB64);
      const response  = decodeBurpField(respField, respB64);
      if (!request && !response) return null;
      return { method, request, response };
    }).filter(Boolean);

    await insertVuln(projectId, userId, {
      name:        stripHtml(issue.name) || 'Unnamed Finding',
      category:    'Burp Suite',
      severity:    BURP_SEV[String(issue.severity || '').toLowerCase().trim()] || 'medium',
      description: [stripHtml(issue.issueBackground), stripHtml(issue.issueDetail)].filter(Boolean).join('\n\n'),
      remediation: [stripHtml(issue.remediationBackground), stripHtml(issue.remediationDetail)].filter(Boolean).join('\n\n'),
      notes:       [issue.location && `Location: ${stripHtml(issue.location)}`, issue.confidence && `Confidence: ${stripHtml(issue.confidence)}`].filter(Boolean).join('\n'),
      targetId:    target?.id || null,
      httpProofs,
    });
    imported++;
  }
  return { imported, targets_created: targetsCreated };
}

// ── Nessus parser ───────────────────────────────────────────────────────
const NESSUS_SEV = { 0:'info', 1:'low', 2:'medium', 3:'high', 4:'critical' };

async function parseNessus(xml, projectId, userId, targetMap) {
  const parser = new XMLParser({
    ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => ['Report','ReportHost','ReportItem','tag'].includes(n),
  });
  const root = parser.parse(xml)?.NessusClientData_v2;
  if (!root) throw new Error('Invalid Nessus XML — missing <NessusClientData_v2> root');

  const reports = [].concat(root.Report || []);
  let imported = 0, targetsCreated = 0;

  for (const report of reports) {
    for (const reportHost of [].concat(report.ReportHost || [])) {
      // Prefer FQDN over IP
      const tags   = [].concat(reportHost.HostProperties?.tag || []);
      const fqdn   = tags.find(t => t['@_name'] === 'host-fqdn')?.['#text'];
      const ip     = tags.find(t => t['@_name'] === 'host-ip')?.['#text'];
      const host   = fqdn || ip || reportHost['@_name'] || null;
      const target = await upsertTarget(projectId, host, userId, targetMap);
      if (target?.created) targetsCreated++;

      for (const item of [].concat(reportHost.ReportItem || [])) {
        const sevNum = parseInt(item['@_severity'] || '0', 10);
        if (sevNum === 0) continue;  // skip informational noise (open ports, banners, etc.)

        const cvssVector = item.cvss3_vector || item.cvss_vector || null;
        const cvssScore  = parseFloat(item.cvss3_base_score || item.cvss_base_score || '') || null;
        const cve        = item.cve ? String(item.cve).trim() : null;

        const notes = [
          item['@_pluginFamily'] && `Family: ${item['@_pluginFamily']}`,
          item['@_port'] && item['@_port'] !== '0' && `Port: ${item['@_port']}/${item['@_protocol'] || 'tcp'}`,
          item['@_svc_name'] && `Service: ${item['@_svc_name']}`,
          cve && `CVE: ${cve}`,
          item.plugin_output && `Scanner output:\n${stripHtml(item.plugin_output)}`,
        ].filter(Boolean).join('\n');

        await db.query(
          `INSERT INTO custom_vulns
             (project_id, name, category, severity, description, remediation, notes,
              items, payloads, evidence, target_id, cvss_vector, cvss_score, created_by, updated_by)
           VALUES ($1,$2,'Nessus',$3,$4,$5,$6,'[]','[]','[]',$7,$8,$9,$10,$10)`,
          [
            projectId,
            stripHtml(item['@_pluginName']) || 'Unnamed Finding',
            NESSUS_SEV[sevNum] || 'medium',
            [stripHtml(item.synopsis), stripHtml(item.description)].filter(Boolean).join('\n\n'),
            stripHtml(item.solution),
            notes,
            target?.id || null,
            cvssVector,
            cvssScore,
            userId,
          ]
        );
        imported++;
      }
    }
  }
  return { imported, targets_created: targetsCreated };
}

// ── OWASP ZAP parser ────────────────────────────────────────────────────
const ZAP_SEV = { 0:'info', 1:'low', 2:'medium', 3:'high' };
const ZAP_CONF = { 0:'False Positive', 1:'Low', 2:'Medium', 3:'High', 4:'Confirmed' };

async function parseZap(xml, projectId, userId, targetMap) {
  const parser = new XMLParser({
    ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => ['site','alertitem','instance'].includes(n),
  });
  const root = parser.parse(xml)?.OWASPZAPReport;
  if (!root) throw new Error('Invalid ZAP XML — missing <OWASPZAPReport> root');

  const sites = [].concat(root.site || []);
  let imported = 0, targetsCreated = 0;

  for (const site of sites) {
    const host   = site['@_host'] || extractHostname(site['@_name']) || null;
    const target = await upsertTarget(projectId, host, userId, targetMap);
    if (target?.created) targetsCreated++;

    for (const alert of [].concat(site.alerts?.alertitem || [])) {
      const riskCode = parseInt(alert.riskcode ?? '2', 10);
      const confCode = parseInt(alert.confidence ?? '2', 10);

      const instances = [].concat(alert.instances?.instance || []);
      const uriList   = [...new Set(instances.map(i => i.uri).filter(Boolean))].slice(0, 10);

      const notes = [
        ZAP_CONF[confCode] && `Confidence: ${ZAP_CONF[confCode]}`,
        alert.cweid && `CWE: CWE-${alert.cweid}`,
        uriList.length && `Affected URLs:\n${uriList.join('\n')}`,
        alert.otherinfo && `Other info:\n${stripHtml(alert.otherinfo)}`,
      ].filter(Boolean).join('\n');

      await insertVuln(projectId, userId, {
        name:        stripHtml(alert.name || alert.alert) || 'Unnamed Alert',
        category:    'OWASP ZAP',
        severity:    ZAP_SEV[riskCode] ?? 'medium',
        description: stripHtml(alert.desc),
        remediation: stripHtml(alert.solution),
        notes,
        targetId:    target?.id || null,
      });
      imported++;
    }
  }
  return { imported, targets_created: targetsCreated };
}

// ── Nmap parser ─────────────────────────────────────────────────────────
// A diferencia de Burp/Nessus/ZAP (que reportan VULNERABILIDADES), un scan
// de Nmap reporta puertos/servicios — ROADMAP.md: "complementa Nessus para
// el inventario de puertos/servicios". No crea custom_vulns: puebla
// targets + target_ports directamente, el mismo dato que ya se ve en la
// pestaña Targets de cada target. `-oX` es la forma estándar de generar el
// XML (ej. `nmap -sV -oX scan.xml <hosts>`).
async function parseNmap(xml, projectId, userId, targetMap) {
  const parser = new XMLParser({
    ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => ['host', 'address', 'hostname', 'port'].includes(n),
  });
  const root = parser.parse(xml)?.nmaprun;
  if (!root) throw new Error('Invalid Nmap XML — missing <nmaprun> root (use nmap -oX)');

  const hosts = [].concat(root.host || []);
  let imported = 0, targetsCreated = 0;

  // target_ports no tiene UNIQUE(target_id,port,protocol) — sin este chequeo,
  // reimportar el mismo scan (o dos scans solapados) duplicaría filas cada
  // vez. Se arma una sola vez, como targetMap más arriba.
  const { rows: existingPorts } = await db.query(`SELECT target_id, port, protocol FROM target_ports`);
  const portSet = new Set(existingPorts.map(p => `${p.target_id}:${p.port}:${p.protocol}`));

  for (const host of hosts) {
    if (host.status?.['@_state'] !== 'up') continue; // hosts caídos/no respondieron — nada real que importar

    const addresses    = [].concat(host.address || []);
    const hostnames     = [].concat(host.hostnames?.hostname || []);
    // Preferir el hostname "user" (el que el propio Nmap resolvió/te dieron)
    // sobre la IP, mismo criterio que parseNessus prefiere FQDN sobre IP.
    const userHostname = hostnames.find(h => h['@_type'] === 'user')?.['@_name'];
    const ipv4          = addresses.find(a => a['@_addrtype'] === 'ipv4')?.['@_addr'];
    const hostValue     = userHostname || ipv4 || addresses.find(a => a['@_addrtype'] !== 'mac')?.['@_addr'];
    if (!hostValue) continue;

    const target = await upsertTarget(projectId, hostValue, userId, targetMap);
    if (!target) continue;
    if (target.created) targetsCreated++;

    for (const port of [].concat(host.ports?.port || [])) {
      if (port.state?.['@_state'] !== 'open') continue; // solo lo accionable — mismo criterio que Nessus salteando severity=0

      const portNum  = parseInt(port['@_portid'], 10);
      const protocol = String(port['@_protocol'] || 'tcp').toLowerCase();
      if (!portNum || (protocol !== 'tcp' && protocol !== 'udp')) continue; // target_ports.protocol solo acepta tcp/udp

      const key = `${target.id}:${portNum}:${protocol}`;
      if (portSet.has(key)) continue;
      portSet.add(key);

      const svc = port.service || {};
      const version = [svc['@_product'], svc['@_version'], svc['@_extrainfo'] && `(${svc['@_extrainfo']})`]
        .filter(Boolean).join(' ') || null;

      await db.query(
        `INSERT INTO target_ports (target_id, port, protocol, state, service, version, notes, added_by)
         VALUES ($1,$2,$3,'open',$4,$5,'Imported from Nmap scan',$6)`,
        [target.id, portNum, protocol, svc['@_name'] || null, version, userId]
      );
      imported++;
    }
  }
  return { imported, targets_created: targetsCreated };
}

// ── Auto-detect + single endpoint ───────────────────────────────────────
function detectFormat(xml) {
  if (/<issues[\s>]/i.test(xml))              return 'burp';
  if (/NessusClientData/i.test(xml))          return 'nessus';
  if (/OWASPZAPReport/i.test(xml))            return 'zap';
  if (/<nmaprun[\s>]/i.test(xml))              return 'nmap';
  return null;
}

router.post('/scan', requireEditor, upload.single('file'), async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const xml    = req.file.buffer.toString('utf8');
    const format = detectFormat(xml);
    if (!format) return res.status(400).json({ error: 'Unrecognized format — expected Burp Suite, Nessus, OWASP ZAP, or Nmap XML' });

    const projectId = req.params.projectId;
    const { rows: existing } = await db.query('SELECT id, host FROM targets WHERE project_id=$1', [projectId]);
    const targetMap = new Map(existing.map(t => [t.host.toLowerCase(), t.id]));

    let result;
    if (format === 'burp')   result = await parseBurp(xml,   projectId, req.user.id, targetMap);
    if (format === 'nessus') result = await parseNessus(xml, projectId, req.user.id, targetMap);
    if (format === 'zap')    result = await parseZap(xml,    projectId, req.user.id, targetMap);
    if (format === 'nmap')   result = await parseNmap(xml,   projectId, req.user.id, targetMap);

    res.json({ ...result, format });
  } catch (err) {
    next(err);
  }
});

// Keep /burp for backward compatibility
router.post('/burp', requireEditor, upload.single('file'), async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const xml = req.file.buffer.toString('utf8');
    const { rows: existing } = await db.query('SELECT id, host FROM targets WHERE project_id=$1', [req.params.projectId]);
    const targetMap = new Map(existing.map(t => [t.host.toLowerCase(), t.id]));
    const result = await parseBurp(xml, req.params.projectId, req.user.id, targetMap);
    res.json({ ...result, format: 'burp' });
  } catch (err) { next(err); }
});

module.exports = router;
