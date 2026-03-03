# @zovo/crx-permission-analyzer

[![npm version](https://img.shields.io/npm/v/@zovo/crx-permission-analyzer.svg)](https://npmjs.com/package/@zovo/crx-permission-analyzer)
[![CI](https://github.com/theluckystrike/crx-permission-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/theluckystrike/crx-permission-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Discord](https://img.shields.io/badge/Discord-Zovo-blueviolet.svg?logo=discord)](https://discord.gg/zovo)
[![Website](https://img.shields.io/badge/Website-zovo.one-blue)](https://zovo.one)

> Analyze Chrome extension permissions and flag dangerous combinations. CLI tool and Node.js library that reads `manifest.json`, scores each permission by risk level, detects dangerous permission pairings, and outputs a human-readable or JSON report.

Part of the [Zovo](https://zovo.one) family of privacy-first Chrome extension developer tools.

## Install

```bash
npm install @zovo/crx-permission-analyzer
```

## Quick Start

### CLI

```bash
npx @zovo/crx-permission-analyzer manifest.json

# JSON output
npx @zovo/crx-permission-analyzer manifest.json --json

# Exclude optional permissions
npx @zovo/crx-permission-analyzer manifest.json --no-optional
```

The CLI exits with code 1 when risk level is `high` or `critical`, making it suitable for CI pipelines.

### Library

```typescript
import { analyze, analyzePermissions, formatHuman, formatJson } from '@zovo/crx-permission-analyzer';

// Analyze from a manifest file
const result = await analyze('./manifest.json');
console.log(`Risk: ${result.riskLevel} (score: ${result.riskScore})`);
console.log(formatHuman(result));

// Analyze raw permission arrays
const result2 = analyzePermissions(
  ['tabs', 'cookies'],
  ['bookmarks'],
  ['https://*/*']
);
console.log(formatJson(result2));
```

## API

### `analyze(manifestPath, options?)`

Reads a `manifest.json` file and returns a full permission analysis.

| Parameter | Type | Description |
|-----------|------|-------------|
| `manifestPath` | `string` | Path to manifest.json |
| `options.outputFormat` | `'json' \| 'human'` | Output format (default: `'human'`) |
| `options.includeOptional` | `boolean` | Include optional permissions (default: `true`) |

Returns `Promise<PermissionAnalysis>`.

### `analyzePermissions(permissions, optionalPermissions?, hostPermissions?)`

Analyzes raw permission arrays without reading a file. Returns `PermissionAnalysis`.

### `parseManifest(manifestPath)`

Extracts `permissions`, `optionalPermissions`, and `hostPermissions` arrays from a manifest file.

### `formatHuman(analysis)` / `formatJson(analysis)`

Format a `PermissionAnalysis` result as human-readable text or JSON string.

## Risk Levels

| Level | Score | Examples |
|-------|-------|---------|
| LOW | 1 | `storage`, `alarms`, `activeTab`, `notifications` |
| MEDIUM | 2 | `bookmarks`, `downloads`, `webNavigation`, `identity` |
| HIGH | 5 | `cookies`, `tabs`, `scripting`, `history`, `geolocation` |
| CRITICAL | 10 | `<all_urls>`, `debugger`, `proxy`, `nativeMessaging` |

Dangerous combinations (e.g. `<all_urls>` + `cookies`) add bonus points to the score.

## See Also

### Related Zovo Repositories

- [crx-manifest-validator](https://github.com/theluckystrike/crx-manifest-validator) - Validate manifest.json files
- [crx-extension-size-analyzer](https://github.com/theluckystrike/crx-extension-size-analyzer) - Analyze extension bundle size
- [chrome-extension-starter-mv3](https://github.com/theluckystrike/chrome-extension-starter-mv3) - Production-ready MV3 starter template
- [chrome-storage-plus](https://github.com/theluckystrike/chrome-storage-plus) - Type-safe storage wrapper

### Zovo Chrome Extensions

- [Zovo Tab Manager](https://chrome.google.com/webstore/detail/zovo-tab-manager) - Manage tabs efficiently
- [Zovo Focus](https://chrome.google.com/webstore/detail/zovo-focus) - Block distractions
- [Zovo Permissions Scanner](https://chrome.google.com/webstore/detail/zovo-permissions-scanner) - Check extension privacy grades

Visit [zovo.one](https://zovo.one) for more information.

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/permission-analysis`
3. **Make** your changes and add tests
4. **Test** your changes: `npm test`
5. **Commit** your changes: `git commit -m 'Add new feature'`
6. **Push** to the branch: `git push origin feature/permission-analysis`
7. **Submit** a Pull Request

## License

MIT — [Zovo](https://zovo.one)

---

*Built by developers, for developers. No compromises on privacy.*
