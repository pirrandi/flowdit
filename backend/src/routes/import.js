const express   = require('express');
const multer    = require('multer');
const { XMLParser } = require('fast-xml-parser');
const db        = require('../db');
const { requireAuth }                        = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');

const router = express.Router({ mergeParams: true });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

router.use(requireAuth, requireProjectAccess);

const SEVERITY_MAP = {
  'high':          'high',
  'medium':        'medium',
  'low':           'low',
  'information':   'info',
  'informational': 'info',
  'false positive':'info',
};

function stripHtml(val) {
  if (val == null) return '';
  return String(val)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&lt;/g,  '<').replace(/&gt;/g,  '>')
    .replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function extractHostname(hostEl) {
  const raw = typeof hostEl === 'object' ? String(hostEl['#text'] || '') : String(hostEl || '');
  try { return new URL(raw.trim()).hostname; } catch { return raw.trim(); }
}

// ── POST /burp ─────────────────────────────────────────────────────────
router.post('/burp', requireEditor, upload.single('file'), async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const xml = req.file.buffer.toString('utf8');
    const parser = new XMLParser({
      ignoreAttributes:    false,
      attributeNamePrefix: '@_',
      cdataPropName:       '__cdata',
      isArray: (name) => name === 'issue',
    });

    const parsed = parser.parse(xml);
    const root   = parsed?.issues;
    if (!root) return res.status(400).json({ error: 'Invalid Burp XML — missing <issues> root element' });

    let issues = root.issue || [];
    if (!Array.isArray(issues)) issues = [issues];
    if (!issues.length) return res.json({ imported: 0, targets_created: 0 });

    const projectId = req.params.projectId;

    // Pre-load targets for host matching
    const { rows: existingTargets } = await db.query(
      'SELECT id, host FROM targets WHERE project_id = $1', [projectId]
    );
    const targetMap = new Map(existingTargets.map(t => [t.host.toLowerCase(), t.id]));

    let imported = 0;
    let targetsCreated = 0;

    for (const issue of issues) {
      const name     = stripHtml(issue.name) || 'Unnamed Finding';
      const rawSev   = String(issue.severity || '').toLowerCase().trim();
      const severity = SEVERITY_MAP[rawSev] || 'medium';

      const hostRaw  = issue.host ? extractHostname(issue.host) : null;

      // Merge background + detail for description and remediation
      const description = [
        stripHtml(issue.issueBackground),
        stripHtml(issue.issueDetail),
      ].filter(Boolean).join('\n\n');

      const remediation = [
        stripHtml(issue.remediationBackground),
        stripHtml(issue.remediationDetail),
      ].filter(Boolean).join('\n\n');

      const location   = stripHtml(issue.location);
      const confidence = stripHtml(issue.confidence);
      const notes = [
        location   ? `Location: ${location}`     : '',
        confidence ? `Confidence: ${confidence}` : '',
      ].filter(Boolean).join('\n').trim();

      // Match existing target or create one
      let targetId = null;
      if (hostRaw) {
        const key = hostRaw.toLowerCase();
        if (targetMap.has(key)) {
          targetId = targetMap.get(key);
        } else {
          const { rows } = await db.query(
            `INSERT INTO targets (project_id, host, type, scope, notes, added_by)
             VALUES ($1, $2, 'domain', 'in', '', $3) RETURNING id`,
            [projectId, hostRaw, req.user.id]
          );
          targetId = rows[0].id;
          targetMap.set(key, targetId);
          targetsCreated++;
        }
      }

      await db.query(
        `INSERT INTO custom_vulns
           (project_id, name, category, severity, description, remediation, notes,
            items, payloads, evidence, target_id, created_by, updated_by)
         VALUES ($1,$2,'Burp Suite',$3,$4,$5,$6,'[]','[]','[]',$7,$8,$8)`,
        [projectId, name, severity, description, remediation, notes, targetId, req.user.id]
      );
      imported++;
    }

    res.json({ imported, targets_created: targetsCreated });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
