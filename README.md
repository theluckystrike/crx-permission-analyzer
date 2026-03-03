# @zovo/crx-permission-analyzer

[![CI](https://github.com/theluckystrike/crx-permission-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/theluckystrike/crx-permission-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Analyze Chrome extension permissions and flag dangerous combinations. CLI tool and Node.js library that reads `manifest.json`, scores each permission by risk level, detects dangerous permission pairings, and outputs a human-readable or JSON report.

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

## Related

- [crx-manifest-validator](https://github.com/theluckystrike/crx-manifest-validator) -- Validate manifest.json files
- [crx-extension-size-analyzer](https://github.com/theluckystrike/crx-extension-size-analyzer) -- Analyze extension bundle size
- [chrome-extension-starter-mv3](https://github.com/theluckystrike/chrome-extension-starter-mv3) -- Production-ready MV3 starter template

## License

MIT -- [Zovo](https://zovo.one)
