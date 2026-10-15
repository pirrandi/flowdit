// Resets and repopulates the public demo account (username "demo", password
// "demo") with a realistic pentest engagement — targets, findings across all
// severities and remediation states, WSTG/PortSwigger progress, and tickets.
//
// Safe to run repeatedly: it deletes the "demo" user first (which cascades
// through its org/project/everything, per the FK ON DELETE CASCADE chains in
// migrate.js) and rebuilds from scratch. That's the whole reset story — no
// separate "clean up mutations" logic needed, since a public demo visitor
// can edit/delete data freely (see middleware/auth.js's blockDemoDestructive
// for the couple of exceptions that would otherwise brick the demo for
// everyone until the next reset).
//
// Intended to run on a cron schedule on the demo.flowdit.space deploy only,
// e.g. every 30 minutes: */30 * * * * cd /var/www/flowdit-demo/backend &&
// DEMO_MODE=true node src/db/seed-demo.js >> /var/log/flowdit-demo-seed.log 2>&1
//
// Run manually: node src/db/seed-demo.js

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../..', '.env') });
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('./index');

const DEMO_USERNAME = 'demo';
const DEMO_EMAIL    = 'demo@flowdit.space';
const DEMO_PASSWORD = 'demo';

const TEMPLATE_NAMES = [
  'SQL Injection', 'Stored Cross-Site Scripting (XSS)', 'Server-Side Request Forgery (SSRF)',
  'Insecure Direct Object Reference (IDOR)', 'Broken Access Control', 'CORS Misconfiguration',
  'Weak Password Policy', 'SSL/TLS Misconfiguration', 'Missing Security Headers', 'Clickjacking',
];

async function seedDemo() {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    // Deleted in this order deliberately: projects/organizations cascade
    // cleanly through project_id/organization_id (targets, vulns, tickets,
    // members, ...). Deleting the user row first would hit the same rows via
    // non-cascading audit FKs (targets.added_by, custom_vulns.created_by,
    // etc.) in the same statement, which Postgres can evaluate before the
    // owner_id cascade has run — a known same-statement FK ordering trap.
    const { rows: existing } = await client.query('SELECT id FROM users WHERE username=$1', [DEMO_USERNAME]);
    if (existing.length) {
      const oldId = existing[0].id;
      await client.query('DELETE FROM projects WHERE owner_id=$1', [oldId]);
      await client.query('DELETE FROM organizations WHERE owner_id=$1', [oldId]);
      await client.query('DELETE FROM users WHERE id=$1', [oldId]);
    }

    const hash = await bcrypt.hash(DEMO_PASSWORD, 12);
    const { rows: [user] } = await client.query(
      `INSERT INTO users (username, email, password, avatar_color) VALUES ($1,$2,$3,$4) RETURNING id`,
      [DEMO_USERNAME, DEMO_EMAIL, hash, '#7c3aed']
    );

    const { rows: [org] } = await client.query(
      `INSERT INTO organizations (name, owner_id, is_personal) VALUES ($1,$2,true) RETURNING id`,
      ['Demo Organization', user.id]
    );
    await client.query(
      `INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1,$2,'owner')`,
      [org.id, user.id]
    );

    const portalToken = crypto.randomBytes(24).toString('hex');
    const { rows: [project] } = await client.query(
      `INSERT INTO projects (
         name, target, description, owner_id, status, organization_id,
         client_view_enabled, tickets_enabled, show_findings, show_wstg_progress, show_targets,
         date_start, date_end, date_report, portal_token
       ) VALUES (
         $1,$2,$3,$4,'active',$5,
         true,true,true,true,true,
         NOW() - INTERVAL '28 days', NOW() - INTERVAL '3 days', NOW() - INTERVAL '1 day', $6
       ) RETURNING id`,
      [
        'Acme Corp — External Web App Pentest', 'acme-corp.demo',
        "External black-box penetration test of Acme Corp's customer-facing web application, API, and administrative interfaces.",
        user.id, org.id, portalToken,
      ]
    );
    await client.query(
      `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'owner')`,
      [project.id, user.id]
    );

    // ── Targets ──────────────────────────────────────────────────────
    const targetDefs = [
      { host: 'app.acme-corp.demo',    type: 'domain', scope: 'in' },
      { host: 'api.acme-corp.demo',    type: 'domain', scope: 'in' },
      { host: 'admin.acme-corp.demo',  type: 'domain', scope: 'in' },
      { host: '203.0.113.10',          type: 'ip',     scope: 'in' },
      { host: 'legacy.acme-corp.demo', type: 'domain', scope: 'out' },
    ];
    const targetId = {};
    for (const t of targetDefs) {
      const { rows: [row] } = await client.query(
        `INSERT INTO targets (project_id, host, type, scope, added_by) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
        [project.id, t.host, t.type, t.scope, user.id]
      );
      targetId[t.host] = row.id;
    }

    await client.query(
      `INSERT INTO target_ports (target_id, port, protocol, service, version) VALUES
       ($1,443,'tcp','https','nginx 1.24.0'), ($1,80,'tcp','http','nginx 1.24.0')`,
      [targetId['app.acme-corp.demo']]
    );
    await client.query(
      `INSERT INTO target_ports (target_id, port, protocol, service, version) VALUES
       ($1,443,'tcp','https','Kestrel'), ($1,8443,'tcp','https','Kestrel (internal)')`,
      [targetId['api.acme-corp.demo']]
    );
    await client.query(
      `INSERT INTO target_ports (target_id, port, protocol, service, version) VALUES
       ($1,22,'tcp','ssh','OpenSSH 8.9'), ($1,443,'tcp','https','nginx 1.24.0'), ($1,25,'tcp','smtp','Postfix')`,
      [targetId['203.0.113.10']]
    );

    await client.query(
      `INSERT INTO target_endpoints (target_id, path, method, status_code, interesting) VALUES
       ($1,'/login','GET',200,false),
       ($1,'/account/settings','GET',200,false),
       ($1,'/api/v1/export','POST',200,true)`,
      [targetId['app.acme-corp.demo']]
    );
    await client.query(
      `INSERT INTO target_endpoints (target_id, path, method, status_code, interesting) VALUES
       ($1,'/v1/users','GET',200,true),
       ($1,'/v1/users/{id}/invoices','GET',200,true),
       ($1,'/v1/internal/debug','GET',403,true)`,
      [targetId['api.acme-corp.demo']]
    );

    // ── Findings (seeded from the built-in template library) ──────────
    const { rows: templates } = await client.query(
      `SELECT name, category, severity, cwe, description, remediation
       FROM vuln_templates WHERE is_builtin AND name = ANY($1)`,
      [TEMPLATE_NAMES]
    );
    const tpl = Object.fromEntries(templates.map(t => [t.name, t]));

    async function addVuln(name, overrides = {}) {
      const t = tpl[name];
      const {
        target_id = null, remediation_status = 'open', remediated_at = null,
        retest_date = null, retest_notes = null, verified_at = null, verified_by = null,
        cvss_score = null, cvss_vector = null, created_days_ago = 14,
      } = overrides;
      await client.query(
        `INSERT INTO custom_vulns (
           project_id, name, category, description, remediation, severity, cwe, status,
           target_id, remediation_status, remediated_at, retest_date, retest_notes,
           verified_at, verified_by, cvss_score, cvss_vector, created_by, updated_by,
           created_at, updated_at, client_visible
         ) VALUES (
           $1,$2,$3,$4,$5,$6,$7,'done',
           $8,$9,$10,$11,$12,
           $13,$14,$15,$16,$17,$17,
           NOW() - $18::interval, NOW() - ($18::interval / 2),
           -- Published, so the demo's client portal shows them (drafts stay hidden).
           true
         )`,
        [
          project.id, t.name, t.category, t.description, t.remediation, t.severity, t.cwe,
          target_id, remediation_status, remediated_at, retest_date, retest_notes,
          verified_at, verified_by, cvss_score, cvss_vector, user.id,
          `${created_days_ago} days`,
        ]
      );
    }

    await addVuln('SQL Injection', {
      target_id: targetId['api.acme-corp.demo'], created_days_ago: 24,
      cvss_score: 9.8, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    });
    await addVuln('Stored Cross-Site Scripting (XSS)', {
      target_id: targetId['app.acme-corp.demo'], created_days_ago: 22,
    });
    await addVuln('Server-Side Request Forgery (SSRF)', {
      target_id: targetId['api.acme-corp.demo'], created_days_ago: 20,
      remediation_status: 'remediated', remediated_at: new Date(Date.now() - 3 * 86400000),
      retest_date: new Date(Date.now() + 4 * 86400000), retest_notes: 'Client patched outbound request allow-list — scheduled for retest.',
    });
    await addVuln('Insecure Direct Object Reference (IDOR)', {
      target_id: targetId['app.acme-corp.demo'], created_days_ago: 21,
      cvss_score: 7.5, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
      remediation_status: 'verified_closed',
      remediated_at: new Date(Date.now() - 9 * 86400000),
      verified_at: new Date(Date.now() - 2 * 86400000), verified_by: user.id,
    });
    await addVuln('Broken Access Control', {
      target_id: targetId['admin.acme-corp.demo'], created_days_ago: 18,
    });
    await addVuln('CORS Misconfiguration', {
      target_id: targetId['api.acme-corp.demo'], created_days_ago: 16,
    });
    await addVuln('Weak Password Policy', {
      target_id: targetId['app.acme-corp.demo'], created_days_ago: 15,
    });
    await addVuln('SSL/TLS Misconfiguration', {
      target_id: targetId['203.0.113.10'], created_days_ago: 12,
      remediation_status: 'remediated', remediated_at: new Date(Date.now() - 1 * 86400000),
    });
    await addVuln('Missing Security Headers', {
      target_id: targetId['app.acme-corp.demo'], created_days_ago: 8,
    });
    await addVuln('Clickjacking', {
      target_id: targetId['app.acme-corp.demo'], created_days_ago: 4,
    });

    const { rows: vulnRows } = await client.query(
      `SELECT id, name FROM custom_vulns WHERE project_id=$1`, [project.id]
    );
    const vulnId = Object.fromEntries(vulnRows.map(v => [v.name, v.id]));

    // ── WSTG methodology progress ──────────────────────────────────────
    const wstgRows = [
      ['WSTG-INFO-01', 'done', null, 'Recon complete — no significant leakage beyond expected marketing footprint.'],
      ['WSTG-INFO-02', 'done', null, null],
      ['WSTG-CONF-06', 'done', null, 'OPTIONS/TRACE disabled on all in-scope hosts.'],
      ['WSTG-CONF-14', 'fail', vulnId['Missing Security Headers'], 'CSP and X-Frame-Options missing on app.acme-corp.demo.'],
      ['WSTG-ATHN-03', 'done', null, 'Account lockout after 5 attempts, 15 min window.'],
      ['WSTG-ATHN-07', 'fail', vulnId['Weak Password Policy'], 'No complexity or breach-list check on registration.'],
      ['WSTG-ATHZ-02', 'fail', vulnId['Broken Access Control'], null],
      ['WSTG-ATHZ-04', 'fail', vulnId['Insecure Direct Object Reference (IDOR)'], 'Invoice IDs sequential and unauthenticated cross-account access confirmed, then verified fixed on retest.'],
      ['WSTG-SESS-02', 'done', null, 'Secure/HttpOnly/SameSite all present.'],
      ['WSTG-SESS-05', 'done', null, null],
      ['WSTG-INPV-01', 'done', null, 'Reflected XSS: all tested sinks properly encoded.'],
      ['WSTG-INPV-02', 'fail', vulnId['Stored Cross-Site Scripting (XSS)'], 'Profile bio field renders unescaped in the admin dashboard.'],
      ['WSTG-INPV-05', 'fail', vulnId['SQL Injection'], 'Union-based injection confirmed on /v1/search?q=.'],
      ['WSTG-INPV-19', 'fail', vulnId['Server-Side Request Forgery (SSRF)'], 'PDF export endpoint fetches attacker-controlled URLs server-side.'],
      ['WSTG-CLNT-07', 'fail', vulnId['CORS Misconfiguration'], 'ACAO reflects Origin with credentials: true.'],
      ['WSTG-CLNT-09', 'fail', vulnId['Clickjacking'], null],
    ];
    for (const [test_id, status, linked_vuln_id, note] of wstgRows) {
      await client.query(
        `INSERT INTO wstg_progress (project_id, test_id, status, note, linked_vuln_id, target_id, updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [project.id, test_id, status, note, linked_vuln_id || null, targetId['app.acme-corp.demo'], user.id]
      );
    }

    // ── PortSwigger Academy practice progress (personal training tracker,
    // unrelated to the engagement's actual findings) ───────────────────
    const psRows = [
      ['PS-01', 0], ['PS-01', 1], ['PS-01', 10],
      ['PS-02', 0], ['PS-02', 1],
      ['PS-13', 0], ['PS-13', 8],
      ['PS-23', 0],
    ];
    for (const [cat_id, lab_idx] of psRows) {
      await client.query(
        `INSERT INTO ps_progress (project_id, cat_id, lab_idx, done, updated_by) VALUES ($1,$2,$3,true,$4)`,
        [project.id, cat_id, lab_idx, user.id]
      );
    }

    // ── Tickets (client communication thread) ──────────────────────────
    async function addTicket(title, vulnName, status, clientName, clientEmail, replies) {
      const { rows: [ticket] } = await client.query(
        `INSERT INTO tickets (project_id, vuln_id, title, status, opened_by, client_name, client_email)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
        [project.id, vulnName ? vulnId[vulnName] : null, title, status, user.id, clientName, clientEmail]
      );
      for (const body of replies) {
        await client.query(
          `INSERT INTO ticket_replies (ticket_id, body, author_id) VALUES ($1,$2,$3)`,
          [ticket.id, body, user.id]
        );
      }
    }

    await addTicket(
      'Confirm SQL injection finding — need a retest window',
      'SQL Injection', 'in_review', 'Priya Shah', 'priya.shah@acme-corp.demo',
      [
        'Thanks for the writeup — engineering has a fix branched off. Can we schedule a retest for early next week?',
        'Works for us. We\'ll confirm once the retest is booked and share the request/response pair used to validate the patch.',
      ]
    );
    await addTicket(
      'Question about the CORS misconfiguration risk',
      'CORS Misconfiguration', 'open', 'Priya Shah', 'priya.shah@acme-corp.demo',
      ['Is this exploitable without an existing authenticated session, or does it require the victim to already be logged in?']
    );
    await addTicket(
      'Retest confirmed — SSRF fix verified',
      'Server-Side Request Forgery (SSRF)', 'closed', 'Marcus Webb', 'marcus.webb@acme-corp.demo',
      ['Outbound allow-list is in place and the PDF export no longer follows redirects to internal ranges. Closing this out — nice catch.']
    );

    await client.query('COMMIT');
    console.log(`✅ Demo reset — login as ${DEMO_USERNAME}/${DEMO_PASSWORD}`);
    console.log(`   Project: "Acme Corp — External Web App Pentest" (${vulnRows.length} findings, ${wstgRows.length} WSTG checks, 3 tickets)`);
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

if (require.main === module) {
  seedDemo()
    .then(() => process.exit(0))
    .catch(err => { console.error('❌ Demo seed failed:', err); process.exit(1); });
}

module.exports = { seedDemo, DEMO_USERNAME, DEMO_PASSWORD };
