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

module.exports = { targetBelongsToProject, vulnBelongsToProject };
