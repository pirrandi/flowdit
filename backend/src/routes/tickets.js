const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const mailer   = require('../services/mailer');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');
const { vulnBelongsToProject } = require('../services/ownership');
const { decrypt } = require('../utils/crypto');
const github    = require('../services/github');

router.use(requireAuth, requireProjectAccess);

// ── TICKETS ───────────────────────────────────────────────────────

// GET all tickets for a project
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT t.*,
              u.username AS opened_by_username, u.avatar_color AS opened_by_color,
              v.name AS vuln_name,
              gi.external_url AS github_url,
              (SELECT COUNT(*) FROM ticket_replies r WHERE r.ticket_id = t.id)::int AS reply_count
       FROM tickets t
       LEFT JOIN users u ON u.id = t.opened_by
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       LEFT JOIN ticket_integrations gi ON gi.ticket_id = t.id AND gi.provider = 'github'
       WHERE t.project_id = $1
       ORDER BY t.updated_at DESC`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// GET single ticket with replies
router.get('/:ticketId', async (req, res, next) => {
  try {
    const { rows: tickets } = await db.query(
      `SELECT t.*,
              u.username AS opened_by_username, u.avatar_color AS opened_by_color,
              v.name AS vuln_name,
              gi.external_url AS github_url
       FROM tickets t
       LEFT JOIN users u ON u.id = t.opened_by
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       LEFT JOIN ticket_integrations gi ON gi.ticket_id = t.id AND gi.provider = 'github'
       WHERE t.id = $1 AND t.project_id = $2`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!tickets.length) return res.status(404).json({ error: 'Ticket not found' });

    const { rows: replies } = await db.query(
      `SELECT r.*, u.username AS author_username, u.avatar_color AS author_color
       FROM ticket_replies r
       LEFT JOIN users u ON u.id = r.author_id
       WHERE r.ticket_id = $1
       ORDER BY r.created_at ASC`,
      [req.params.ticketId]
    );
    res.json({ ...tickets[0], replies });
  } catch (err) { next(err); }
});

// POST create ticket — team members or portal users
router.post('/', [
  body('title').trim().isLength({ min: 1, max: 300 }),
  body('description').optional().trim(),
  body('vuln_id').optional().isUUID(),
  body('client_name').optional().trim().isLength({ max: 200 }),
  body('client_email').optional().trim().isEmail().normalizeEmail(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { rows: proj } = await db.query(
    `SELECT tickets_enabled FROM projects WHERE id=$1`, [req.params.projectId]
  );
  if (!proj[0]?.tickets_enabled) {
    return res.status(403).json({ error: 'Tickets are not enabled for this project' });
  }

  const { title, description = '' } = req.body;
  const validVulnId = await vulnBelongsToProject(req.body.vuln_id, req.params.projectId);

  if (req.isPortal) {
    // Portal user — no user account, store client_name/email instead
    const clientName  = req.body.client_name?.trim()  || 'Client';
    const clientEmail = req.body.client_email?.trim()  || null;
    try {
      const { rows } = await db.query(
        `INSERT INTO tickets (project_id, vuln_id, title, description, client_name, client_email)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [req.params.projectId, validVulnId, title, description, clientName, clientEmail]
      );
      return res.status(201).json(rows[0]);
    } catch (err) { return next(err); }
  }

  // Team member
  if (!req.user) return res.status(403).json({ error: 'Authentication required' });
  try {
    const { rows } = await db.query(
      `INSERT INTO tickets (project_id, vuln_id, title, description, opened_by)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.params.projectId, validVulnId, title, description, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// PATCH update ticket status (editors/owner only)
router.patch('/:ticketId', requireEditor, [
  body('status').optional().isIn(['open', 'in_review', 'closed']),
  body('title').optional().trim().isLength({ min: 1, max: 300 }),
  body('description').optional().trim(),
], async (req, res, next) => {
  const allowed = ['status', 'title', 'description'];
  const updates = [], values = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      updates.push(`${f}=$${values.length + 1}`);
      values.push(req.body[f]);
    }
  });
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  updates.push(`updated_at=NOW()`);
  values.push(req.params.ticketId, req.params.projectId);
  try {
    const { rows } = await db.query(
      `UPDATE tickets SET ${updates.join(',')}
       WHERE id=$${values.length - 1} AND project_id=$${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Ticket not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE ticket (editors/owner only)
router.delete('/:ticketId', requireEditor, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM tickets WHERE id=$1 AND project_id=$2 RETURNING title`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Ticket not found' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── GITHUB INTEGRATION (v1 — one-way push) ──────────────────────────
// See GITHUB_INTEGRATION.md for the design and the path to bidirectional
// sync. requireEditor matches the bar for every other ticket mutation.
router.post('/:ticketId/github', requireEditor, async (req, res, next) => {
  try {
    const { rows: proj } = await db.query(
      `SELECT github_repo, github_pat_enc FROM projects WHERE id=$1`, [req.params.projectId]
    );
    if (!proj[0]?.github_repo || !proj[0]?.github_pat_enc) {
      return res.status(400).json({ error: 'GitHub is not configured for this project (Settings → GitHub Integration)' });
    }

    const existing = await db.query(
      `SELECT external_url FROM ticket_integrations WHERE ticket_id=$1 AND provider='github'`,
      [req.params.ticketId]
    );
    if (existing.rows.length) {
      return res.status(409).json({ error: 'Already linked to GitHub', external_url: existing.rows[0].external_url });
    }

    const { rows: tickets } = await db.query(
      `SELECT t.title, t.description, v.name AS vuln_name, v.severity, v.description AS vuln_description, v.remediation
       FROM tickets t
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       WHERE t.id=$1 AND t.project_id=$2`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!tickets.length) return res.status(404).json({ error: 'Ticket not found' });
    const ticket = tickets[0];

    const bodyParts = [];
    if (ticket.description) bodyParts.push(ticket.description);
    if (ticket.vuln_name) {
      bodyParts.push(`\n---\n**Linked finding:** ${ticket.vuln_name}${ticket.severity ? ` (${ticket.severity})` : ''}`);
      if (ticket.vuln_description) bodyParts.push(`\n${ticket.vuln_description}`);
      if (ticket.remediation) bodyParts.push(`\n**Remediation:** ${ticket.remediation}`);
    }
    bodyParts.push(`\n\n_Pushed from Flowdit — this issue is not synced back; status changes here don't reflect in Flowdit._`);

    const pat = decrypt(proj[0].github_pat_enc);
    const issue = await github.createIssue(proj[0].github_repo, pat, {
      title: ticket.title,
      body: bodyParts.join('\n'),
    });

    const { rows: inserted } = await db.query(
      `INSERT INTO ticket_integrations (ticket_id, provider, external_id, external_url, created_by)
       VALUES ($1,'github',$2,$3,$4) RETURNING external_id, external_url`,
      [req.params.ticketId, issue.id, issue.url, req.user.id]
    );
    res.status(201).json(inserted[0]);
  } catch (err) {
    if (err.message?.startsWith('GitHub')) return res.status(502).json({ error: err.message });
    next(err);
  }
});

// ── REPLIES ───────────────────────────────────────────────────────

// POST add reply — team members or portal users
router.post('/:ticketId/replies', [
  body('body').trim().isLength({ min: 1 }),
  body('client_name').optional().trim().isLength({ max: 200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  // Portal: require a session (already enforced by requireProjectAccess)
  // Team: require a real user
  if (!req.isPortal && !req.user) return res.status(403).json({ error: 'Authentication required' });

  try {
    const { rows: ticket } = await db.query(
      `SELECT id, title, client_email, client_name, project_id FROM tickets WHERE id=$1 AND project_id=$2`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!ticket.length) return res.status(404).json({ error: 'Ticket not found' });

    let newReply;

    if (req.isPortal) {
      const clientName = req.body.client_name?.trim() || 'Client';
      const { rows } = await db.query(
        `INSERT INTO ticket_replies (ticket_id, body, client_name) VALUES ($1,$2,$3) RETURNING *`,
        [req.params.ticketId, req.body.body, clientName]
      );
      newReply = { ...rows[0], author_username: clientName, author_color: null };
    } else {
      const { rows } = await db.query(
        `INSERT INTO ticket_replies (ticket_id, body, author_id) VALUES ($1,$2,$3) RETURNING *`,
        [req.params.ticketId, req.body.body, req.user.id]
      );
      // Bump ticket updated_at
      await db.query(`UPDATE tickets SET updated_at=NOW() WHERE id=$1`, [req.params.ticketId]);

      const { rows: full } = await db.query(
        `SELECT r.*, u.username AS author_username, u.avatar_color AS author_color
         FROM ticket_replies r JOIN users u ON u.id = r.author_id
         WHERE r.id=$1`,
        [rows[0].id]
      );
      newReply = full[0];

      // Email notification to client if ticket has client_email
      if (ticket[0].client_email) {
        const { rows: projRows } = await db.query(
          `SELECT name, portal_token FROM projects WHERE id=$1`, [req.params.projectId]
        );
        const proj       = projRows[0];
        const portalUrl  = proj?.portal_token
          ? `${process.env.FRONTEND_URL || ''}/client-login.html?token=${proj.portal_token}`
          : null;
        mailer.sendTicketReplyNotification({
          toEmail:     ticket[0].client_email,
          toName:      ticket[0].client_name,
          projectName: proj?.name || 'Your project',
          ticketTitle: ticket[0].title,
          replyBody:   req.body.body,
          replyAuthor: req.user.username,
          portalUrl,
        }).catch(err => console.error('Email notification failed:', err.message));
      }
    }

    await db.query(`UPDATE tickets SET updated_at=NOW() WHERE id=$1`, [req.params.ticketId]);
    res.status(201).json(newReply);
  } catch (err) { next(err); }
});

// DELETE reply (author or editor)
router.delete('/:ticketId/replies/:replyId', async (req, res, next) => {
  try {
    const { rows: ticket } = await db.query(
      `SELECT id FROM tickets WHERE id=$1 AND project_id=$2`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!ticket.length) return res.status(404).json({ error: 'Ticket not found' });

    const isEditor = ['owner', 'editor'].includes(req.memberRole);
    const { rows } = await db.query(
      `DELETE FROM ticket_replies
       WHERE id=$1 AND ticket_id=$2 ${isEditor ? '' : 'AND author_id=$3'}
       RETURNING id`,
      isEditor
        ? [req.params.replyId, req.params.ticketId]
        : [req.params.replyId, req.params.ticketId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Reply not found or not authorized' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
