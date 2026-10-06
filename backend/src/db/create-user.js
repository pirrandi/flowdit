#!/usr/bin/env node
// Internal user-provisioning CLI — run ON the server, by an operator.
//
// Public self-registration is disabled (see routes/auth.js), so this is the
// supported way to create an account. It talks straight to the DB through the
// same userProvisioning.createUser() the register route uses, so a CLI-created
// account is identical to a self-registered one (personal org + owner
// membership, bcrypt cost 12).
//
// Usage:
//   npm run user:create -- --username <name> --email <email> [--password <pw>]
//   node src/db/create-user.js --username <name> --email <email>
//
// If --password is omitted a strong random one is generated and printed ONCE.
// Loads the repo-root .env the same way migrate.js / seed-demo.js do, so DB_*
// resolve regardless of the directory the operator runs this from.
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../..', '.env') });
const crypto = require('crypto');
const db = require('../db');
const { createUser, UserExistsError } = require('../services/userProvisioning');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--username' || a === '-u') out.username = argv[++i];
    else if (a === '--email' || a === '-e') out.email = argv[++i];
    else if (a === '--password' || a === '-p') out.password = argv[++i];
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

const USAGE = `
Create a Flowdit user account (internal operator tool).

  npm run user:create -- --username <name> --email <email> [--password <pw>]

Options:
  -u, --username   Username: 2-50 chars, letters/numbers/_/- only   (required)
  -e, --email      Email address                                    (required)
  -p, --password   Password: 8-128 chars. Omit to auto-generate.
  -h, --help       Show this help.
`;

// Mirror the exact validation the register route enforces, so the CLI can't
// create an account the login/validation layer would consider malformed.
function validate({ username, email, password }) {
  const errors = [];
  if (!username || !/^[a-zA-Z0-9_-]{2,50}$/.test(username))
    errors.push('username must be 2-50 chars: letters, numbers, _ or - only');
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    errors.push('email must be a valid address');
  if (!password || password.length < 8 || password.length > 128)
    errors.push('password must be 8-128 chars');
  return errors;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || (!args.username && !args.email)) {
    console.log(USAGE);
    process.exit(args.help ? 0 : 1);
  }

  // Auto-generate a strong password when none is given — printed once below.
  const generated = !args.password;
  if (generated) args.password = crypto.randomBytes(18).toString('base64url');

  const errors = validate(args);
  if (errors.length) {
    console.error('Invalid input:');
    errors.forEach(e => console.error('  - ' + e));
    process.exit(1);
  }

  try {
    const user = await createUser({
      username: args.username.trim(),
      email: args.email.trim().toLowerCase(),
      password: args.password,
    });
    console.log('\n✓ User created');
    console.log('  id:       ' + user.id);
    console.log('  username: ' + user.username);
    console.log('  email:    ' + user.email);
    if (generated) {
      console.log('  password: ' + args.password);
      console.log('\n  ⚠ This password is shown ONLY now. Hand it to the user over a secure channel.');
    }
    console.log('');
    process.exit(0);
  } catch (err) {
    if (err instanceof UserExistsError) {
      console.error('\n✗ ' + err.message);
      process.exit(2);
    }
    console.error('\n✗ Failed to create user:', err.message);
    process.exit(1);
  }
}

main().finally(() => { if (db.pool) db.pool.end().catch(() => {}); });
