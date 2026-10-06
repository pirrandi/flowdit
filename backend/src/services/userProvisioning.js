// Shared user provisioning — the single source of truth for "create a user".
//
// Every user MUST own a personal organization for the permission model to hold
// (requireProjectAccess grants access via org membership). A user created
// without an org is a broken account. So user + personal org + owner membership
// are inserted together, transactionally: a crash partway through must not leave
// a user with no org.
//
// This lives in a service (not inline in the register route) because there are
// now two callers: the public register route (gated, see routes/auth.js) and
// the internal CLI tool (db/create-user.js). They must provision identically —
// same bcrypt cost, same org bootstrap — or accounts created one way behave
// differently from the other.
const bcrypt = require('bcryptjs');
const db     = require('../db');

const COLORS = ['#7c3aed', '#2563eb', '#059669', '#dc2626', '#d97706', '#0891b2', '#be185d'];
const BCRYPT_ROUNDS = 12;

class UserExistsError extends Error {
  constructor() {
    super('Username or email already taken');
    this.name = 'UserExistsError';
    this.code = 'USER_EXISTS';
  }
}

// Creates a user and their personal organization in one transaction.
// Returns the user row { id, username, email, avatar_color, created_at }.
// Throws UserExistsError if the username or email is already taken.
// Does NOT validate input or mint tokens — callers own those concerns.
async function createUser({ username, email, password }) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    const exists = await client.query(
      'SELECT id FROM users WHERE username=$1 OR email=$2', [username, email]
    );
    if (exists.rows.length) {
      await client.query('ROLLBACK');
      throw new UserExistsError();
    }

    const hash  = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const color = COLORS[Math.floor(Math.random() * COLORS.length)];
    const { rows } = await client.query(
      `INSERT INTO users (username, email, password, avatar_color)
       VALUES ($1,$2,$3,$4) RETURNING id, username, email, avatar_color, created_at`,
      [username, email, hash, color]
    );
    const user = rows[0];

    const { rows: orgRows } = await client.query(
      `INSERT INTO organizations (name, owner_id, is_personal) VALUES ($1,$2,true) RETURNING id`,
      [`${user.username}'s Organization`, user.id]
    );
    await client.query(
      `INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1,$2,'owner')`,
      [orgRows[0].id, user.id]
    );

    await client.query('COMMIT');
    return user;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { createUser, UserExistsError };
