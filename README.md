# @zovo/crx-permission-analyzer

> Analyze Chrome extension permissions and flag dangerous combinations

A CLI + library tool that analyzes Chrome extension manifest.json files and outputs risk assessments.

## Features

- 📊 **Risk Scoring** - Calculate overall risk score based on permissions
- ⚠️ **Dangerous Combinations** - Detect dangerous permission combinations
- 📝 **Plain English Descriptions** - Explains what each permission allows
- 🔍 **Multiple Output Formats** - Human-readable or JSON output
- 🧪 **Well Tested** - Comprehensive test coverage with vitest
- 📦 **Dual Interface** - Use as CLI tool or import as library

## Installation

```bash
npm install @zovo/crx-permission-analyzer
```

Or run directly with npx:

```bash
npx @zovo/crx-permission-analyzer manifest.json
```

## CLI Usage

### Basic Analysis

```bash
crx-permission-analyzer manifest.json
```

### JSON Output

```bash
crx-permission-analyzer manifest.json --json
```

### Exclude Optional Permissions

```bash
crx-permission-analyzer manifest.json --no-optional
```

## Library Usage

```typescript
import { analyze, formatHuman } from '@zovo/crx-permission-analyzer';

// Analyze a manifest
const result = await analyze('./manifest.json');

console.log(`Risk Level: ${result.riskLevel}`);
console.log(`Risk Score: ${result.riskScore}`);

// Print human-readable report
console.log(formatHuman(result));
```

### API Reference

#### `analyze(manifestPath: string, options?: AnalysisOptions): Promise<PermissionAnalysis>`

Analyzes a manifest.json file and returns a permission analysis.

**Parameters:**
- `manifestPath` - Path to the extension's manifest.json file
- `options` - Optional analysis options

**Returns:** `Promise<PermissionAnalysis>`

#### `formatHuman(analysis: PermissionAnalysis): string`

Formats the analysis as a human-readable report.

#### `formatJson(analysis: PermissionAnalysis): string`

Formats the analysis as JSON.

## Permission Risk Levels

| Level | Description |
|-------|-------------|
| 🟢 LOW | Minimal privacy/security impact (e.g., storage, alarms) |
| 🟡 MEDIUM | Some privacy or functionality impact (e.g., bookmarks, topSites) |
| 🟠 HIGH | Significant security or privacy risk (e.g., cookies, tabs, scripting) |
| 🔴 CRITICAL | Severe security risk, potentially malicious (e.g., <all_urls> + webRequest) |

## Dangerous Combinations

The analyzer automatically detects these dangerous permission combinations:

- `<all_urls>` + `webRequest` - Traffic interception
- `<all_urls>` + `cookies` - Session theft
- `tabs` + `scripting` - Page modification
- And many more...

## Risk Score

The risk score is calculated by summing weights:

- Critical: 10 points
- High: 5 points
- Medium: 2 points
- Low: 1 point

Bonus points are added for dangerous combinations.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build

# Run CLI locally
npm run cli -- manifest.json
```

## License

MIT
