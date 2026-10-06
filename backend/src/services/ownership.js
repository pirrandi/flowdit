const db = require('../db');

// Client-supplied foreign keys (target_id, vuln_id, ...) must be re-validated against
// the project the request is already scoped to — otherwise a project member can smuggle
// in another project's row ID and have its name/host leak back out through a JOIN.
async function targetBelongsToProject(targetId, projectId) {
  if (!targetId) return null;
  const { rows } = await db.query(
    `SELECT id FROM targets WHERE id=$1 AND project_id=$2`,
    [targetId, projectId]
  );
  return rows.length ? targetId : null;
}

async function vulnBelongsToProject(vulnId, projectId) {
  if (!vulnId) return null;
  const { rows } = await db.query(
    `SELECT id FROM custom_vulns WHERE id=$1 AND project_id=$2`,
    [vulnId, projectId]
  );
  return rows.length ? vulnId : null;
}

// Misma query que requireProjectAccess (middleware/project.js) — membership
// directa (project_members) O implícita vía ser owner/admin de la
// organización dueña del proyecto. Extraída acá para poder reusarla fuera
// de Express (ver ws.js: un socket no pasa por el middleware REST, así que
// nada validaba membership al conectar — ver ROADMAP.md § "WebSocket —
// validar membership de proyecto al conectar").
async function userBelongsToProject(userId, projectId) {
  const { rows } = await db.query(
    `SELECT 1
     FROM projects p
     LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = $2
     LEFT JOIN organization_members om ON om.organization_id = p.organization_id AND om.user_id = $2 AND om.role IN ('owner','admin')
     WHERE p.id = $1 AND (pm.user_id IS NOT NULL OR om.user_id IS NOT NULL)`,
    [projectId, userId]
  );
  return rows.length > 0;
}

// The same membership rule as userBelongsToProject, as a correlated SQL
// predicate for queries that span many projects at once (a user's inbox, their
// assigned tasks across projects): `projectCol` is the column holding the
// project id, `userParam` the placeholder holding the user id (e.g. '$1').
// Both are code-supplied identifiers, never user input.
function projectAccessSql(projectCol, userParam) {
  return `EXISTS (
    SELECT 1 FROM projects ap
    LEFT JOIN project_members apm ON apm.project_id = ap.id AND apm.user_id = ${userParam}
    LEFT JOIN organization_members aom ON aom.organization_id = ap.organization_id
          AND aom.user_id = ${userParam} AND aom.role IN ('owner','admin')
    WHERE ap.id = ${projectCol} AND (apm.user_id IS NOT NULL OR aom.user_id IS NOT NULL)
  )`;
}

module.exports = { targetBelongsToProject, vulnBelongsToProject, userBelongsToProject, projectAccessSql };
