export default [{
  files: ['**/index.js', '**/index.test.mjs', '**/eslint.config.mjs'],
  languageOptions: {
    ecmaVersion: 'latest', sourceType: 'module',
    globals: {window: 'readonly', ksu: 'readonly', globalThis: 'readonly'}
  },
  rules: {
    'no-undef': 'error', 'no-unreachable': 'error',
    'no-dupe-keys': 'error', 'no-duplicate-case': 'error',
    'no-redeclare': 'error', 'no-constant-condition': 'error',
    'no-debugger': 'error', 'no-unsafe-finally': 'error',
    'valid-typeof': 'error', 'no-sparse-arrays': 'error'
  }
}];
