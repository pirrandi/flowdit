// Placeholder values that ship in this public repo (docker-compose.yml
// defaults and the .env.example files). Anyone can read them, so a server
// signing JWTs with one of these lets an attacker forge a session for any
// user, including client portal sessions.
const PUBLIC_PLACEHOLDERS = {
  JWT_SECRET: [
    'dev_jwt_secret_change_in_production_00000000000000000000000000000000',
    'CHANGE_THIS_TO_A_RANDOM_64_CHAR_STRING',
    'your_64_char_random_string',
  ],
  DB_PASSWORD: ['changeme', 'CHANGE_THIS_STRONG_PASSWORD', 'your_strong_password'],
};

const MIN_JWT_SECRET_LENGTH = 32;

// Returns a list of human-readable problems; empty means the config is safe.
function checkSecrets(env = process.env) {
  const problems = [];
  const jwtSecret = env.JWT_SECRET || '';

  if (!jwtSecret) {
    problems.push('JWT_SECRET is not set');
  } else if (PUBLIC_PLACEHOLDERS.JWT_SECRET.includes(jwtSecret)) {
    problems.push('JWT_SECRET is a public placeholder from this repository');
  } else if (jwtSecret.length < MIN_JWT_SECRET_LENGTH) {
    problems.push(`JWT_SECRET is shorter than ${MIN_JWT_SECRET_LENGTH} characters`);
  }

  if (PUBLIC_PLACEHOLDERS.DB_PASSWORD.includes(env.DB_PASSWORD)) {
    problems.push('DB_PASSWORD is a public placeholder from this repository');
  }

  return problems;
}

// Production refuses to boot with unsafe secrets; development only warns so
// `docker compose up` keeps working out of the box.
function assertSafeSecrets(env = process.env, log = console) {
  const problems = checkSecrets(env);
  if (!problems.length) return;

  const hint = 'Generate one with: openssl rand -hex 64';
  if (env.NODE_ENV === 'production') {
    throw new Error(`Refusing to start in production: ${problems.join('; ')}. ${hint}`);
  }
  for (const p of problems) log.warn(`⚠️  ${p} (allowed outside production). ${hint}`);
}

module.exports = { checkSecrets, assertSafeSecrets, PUBLIC_PLACEHOLDERS };
