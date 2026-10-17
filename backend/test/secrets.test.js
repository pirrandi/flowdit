const { test } = require('node:test');
const assert = require('node:assert');
const { checkSecrets, assertSafeSecrets, PUBLIC_PLACEHOLDERS } = require('../src/utils/secrets');

const STRONG = 'a'.repeat(64);
const silent = { warn() {} };

test('a strong JWT secret and real DB password pass', () => {
  assert.deepStrictEqual(checkSecrets({ JWT_SECRET: STRONG, DB_PASSWORD: 'x9!real' }), []);
});

test('every published JWT placeholder is rejected', () => {
  for (const s of PUBLIC_PLACEHOLDERS.JWT_SECRET) {
    assert.strictEqual(checkSecrets({ JWT_SECRET: s }).length, 1, s);
  }
});

test('missing or short JWT secrets are rejected', () => {
  assert.match(checkSecrets({})[0], /not set/);
  assert.match(checkSecrets({ JWT_SECRET: 'short' })[0], /shorter/);
});

test('published DB password placeholders are rejected', () => {
  assert.match(checkSecrets({ JWT_SECRET: STRONG, DB_PASSWORD: 'changeme' })[0], /DB_PASSWORD/);
});

test('production refuses to start with a placeholder secret', () => {
  const env = { NODE_ENV: 'production', JWT_SECRET: PUBLIC_PLACEHOLDERS.JWT_SECRET[0] };
  assert.throws(() => assertSafeSecrets(env, silent), /Refusing to start in production/);
});

test('development only warns', () => {
  const warnings = [];
  assertSafeSecrets({ NODE_ENV: 'development' }, { warn: m => warnings.push(m) });
  assert.strictEqual(warnings.length, 1);
});
