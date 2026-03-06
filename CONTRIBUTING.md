# Contributing to crx-permission-analyzer

Thanks for your interest in contributing. This document covers the basics.


GETTING STARTED

1. Fork the repository on GitHub
2. Clone your fork locally
3. Install dependencies with npm install
4. Create a feature branch from main


DEVELOPMENT WORKFLOW

Run the test suite before and after making changes.

```bash
npm test
npm run build
```

The project uses TypeScript with strict mode enabled. All source files live in src/ and tests live in tests/. The test runner is Vitest.


ADDING PERMISSIONS

To add a new permission to the database, edit src/permissions.ts and call addPermission with the permission name, description, risk level, and category. Follow the existing pattern in that file. Add a test case in tests/analyzer.test.ts if the new permission changes expected behavior.


PULL REQUESTS

Keep pull requests focused on a single change. Write a clear description of what changed and why. Make sure all tests pass before submitting. If you are adding new functionality, include tests that cover the new code paths.


ISSUES

Use the issue templates when reporting bugs or requesting features. Include enough detail to reproduce any bugs. For feature requests, explain the use case and expected behavior.


CODE STYLE

Follow the existing patterns in the codebase. Use TypeScript types for all function signatures and return values. Keep functions small and focused. Avoid introducing new dependencies unless absolutely necessary.


LICENSE

By contributing, you agree that your contributions will be licensed under the MIT License.
