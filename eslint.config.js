// @ts-check
import js from '@eslint/js';
import security from 'eslint-plugin-security';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'coverage/', 'node_modules/', 'src/security/common-passwords.ts', 'web/public/'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  security.configs.recommended,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // SQL must always use bound parameters: forbid template literals with
      // interpolation, and string concatenation, as the argument of prepare()/exec().
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.property.name=/^(prepare|exec)$/] > TemplateLiteral[expressions.length>0]",
          message: 'SQL injection risk: use bound parameters (?) instead of interpolation.',
        },
        {
          selector: "CallExpression[callee.property.name=/^(prepare|exec)$/] > BinaryExpression[operator='+']",
          message: 'SQL injection risk: use bound parameters (?) instead of concatenation.',
        },
        {
          selector: "CallExpression[callee.name='eval'], NewExpression[callee.name='Function']",
          message: 'Dynamic code execution is forbidden.',
        },
      ],
      'no-console': ['error', { allow: ['error'] }],
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      // Map lookups and bounded indexes are flagged as false positives by this rule.
      'security/detect-object-injection': 'off',
    },
  },
  {
    // Front-end: UI is built with createElement/textContent only (web/src/dom.ts).
    // Every HTML-from-string sink is banned here, and blocked again at runtime by
    // the Trusted Types CSP, so an XSS needs two independent failures.
    files: ['web/src/**/*.ts'],
    rules: {
      'no-restricted-properties': [
        'error',
        ...['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'srcdoc', 'createContextualFragment', 'parseFromString'].map((property) => ({
          property,
          message: 'Builds HTML from a string (XSS sink). Use h() from dom.ts.',
        })),
        { object: 'document', property: 'write', message: 'XSS sink. Use h() from dom.ts.' },
        { object: 'document', property: 'writeln', message: 'XSS sink. Use h() from dom.ts.' },
        { object: 'localStorage', message: 'Never persist tokens or user data in web storage (ADR 0007).' },
        { object: 'sessionStorage', message: 'Never persist tokens or user data in web storage (ADR 0007).' },
      ],
    },
  },
  {
    // The CLI talks to an operator on a terminal.
    files: ['src/cli.ts'],
    rules: { 'no-console': 'off' },
  },
  {
    files: ['test/**/*.ts', 'vitest.config.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      'security/detect-non-literal-regexp': 'off',
      'security/detect-child-process': 'off',
      // Tests build fixture trees in temporary directories.
      'security/detect-non-literal-fs-filename': 'off',
    },
  },
  { files: ['eslint.config.js'], ...tseslint.configs.disableTypeChecked },
);
