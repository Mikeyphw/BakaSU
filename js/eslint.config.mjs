export default [{
  files: ['**/index.js', '**/index.test.mjs', '**/download.test.mjs', '**/webview/download.js', '**/eslint.config.mjs'],
  languageOptions: {
    ecmaVersion: 'latest', sourceType: 'module',
    globals: {window: 'readonly', ksu: 'readonly', globalThis: 'readonly', URL: 'readonly', Blob: 'readonly', Buffer: 'readonly', FileReader: 'readonly', HTMLAnchorElement: 'readonly', document: 'readonly', location: 'readonly', fetch: 'readonly', console: 'readonly', setTimeout: 'readonly', ksu_download: 'readonly'}
  },
  rules: {
    'no-undef': 'error', 'no-unreachable': 'error',
    'no-dupe-keys': 'error', 'no-duplicate-case': 'error',
    'no-redeclare': 'error', 'no-constant-condition': 'error',
    'no-debugger': 'error', 'no-unsafe-finally': 'error',
    'valid-typeof': 'error', 'no-sparse-arrays': 'error'
  }
}];
