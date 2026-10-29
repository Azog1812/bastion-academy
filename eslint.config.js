// @ts-check
import js from '@eslint/js';
import security from 'eslint-plugin-security';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'coverage/', 'node_modules/', 'src/security/common-passwords.ts'] },
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
    },
  },
  { files: ['eslint.config.js'], ...tseslint.configs.disableTypeChecked },
);
