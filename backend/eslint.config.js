'use strict';

const js = require('@eslint/js');

module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'writable',
        exports: 'writable',
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        setInterval: 'readonly',
        clearTimeout: 'readonly',
        clearInterval: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        fetch: 'readonly',
        globalThis: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        // Web-standard globals Node exposes alongside fetch() — the AI scan
        // tools use them for per-request timeouts and cancellation.
        AbortController: 'readonly',
        AbortSignal: 'readonly',
        DOMException: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': 'off',
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
  {
    // routes/export.js embeds callbacks that Puppeteer serializes and runs
    // inside the target page's browser context, not in Node.
    files: ['src/routes/export.js'],
    languageOptions: {
      globals: {
        document: 'readonly',
        window: 'readonly',
        localStorage: 'readonly',
        navigator: 'readonly',
        Event: 'readonly',
      },
    },
  },
  {
    ignores: ['node_modules/**', 'package/**'],
  },
];
