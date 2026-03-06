# crx-permission-analyzer

Analyze Chrome extension permissions and flag dangerous combinations. A CLI tool and Node.js library that reads manifest.json, scores each permission by risk level, detects dangerous permission pairings, and outputs a human-readable or JSON report.

Supports Manifest V2 and V3. The CLI exits with code 1 when the risk level is high or critical, making it suitable for CI pipelines.


INSTALL

```bash
npm install crx-permission-analyzer
```


CLI USAGE

```bash
crx-permission-analyzer manifest.json

crx-permission-analyzer manifest.json --json

crx-permission-analyzer manifest.json --no-optional
```

CLI flags

    -h, --help         Show help
    -j, --json         Output in JSON format
    -r, --human        Output in human-readable format (default)
    --no-optional      Exclude optional permissions from analysis


LIBRARY USAGE

```typescript
import { analyze, analyzePermissions, formatHuman, formatJson } from 'crx-permission-analyzer';

// Analyze from a manifest file
const result = await analyze('./manifest.json');
console.log(result.riskLevel);
console.log(formatHuman(result));

// Analyze raw permission arrays directly
const result2 = analyzePermissions(
  ['tabs', 'cookies'],       // required permissions
  ['bookmarks'],             // optional permissions
  ['https://*/*']            // host permissions
);
console.log(formatJson(result2));
```


API

analyze(manifestPath, options?)

Reads a manifest.json file and returns a full permission analysis. Options include outputFormat ('json' or 'human', default 'human') and includeOptional (boolean, default true). Returns Promise<PermissionAnalysis>.

analyzePermissions(permissions, optionalPermissions?, hostPermissions?)

Analyzes raw permission arrays without reading a file. Accepts required permissions, optional permissions, and host permissions as separate string arrays. Returns PermissionAnalysis.

parseManifest(manifestPath)

Extracts permissions, optionalPermissions, and hostPermissions arrays from a manifest.json file. Handles both V2 style (permissions with URLs mixed in) and V3 style (separate host_permissions field).

formatHuman(analysis)

Formats a PermissionAnalysis result as a human-readable report with risk levels and color indicators.

formatJson(analysis)

Formats a PermissionAnalysis result as a pretty-printed JSON string.


RISK LEVELS

    LOW (score 1)        storage, alarms, activeTab, notifications, contextMenus
    MEDIUM (score 2)     bookmarks, downloads, webNavigation, identity, sessions
    HIGH (score 5)       cookies, tabs, scripting, history, geolocation, privacy
    CRITICAL (score 10)  <all_urls>, debugger, proxy, nativeMessaging, downloads.open

Dangerous combinations like <all_urls> + cookies or tabs + scripting add bonus points to the total risk score. The library ships with 20 predefined dangerous combination rules.

Overall risk level thresholds are low (below 5), medium (5 to 9), high (10 to 19), and critical (20 or above).


PERMISSION DATABASE

The analyzer includes a built-in database covering 50+ Chrome extension permissions across these categories.

    host           Host pattern permissions like <all_urls>
    api            General Chrome API permissions
    clipboard      Clipboard read and write access
    storage        Local and unlimited storage
    network        Proxy, VPN, and declarativeNetRequest
    tab            Tab access, capture, and grouping
    bookmark       Bookmark read and write
    download       Download management and file opening
    geolocation    Physical location tracking
    notification   Desktop notification access
    privacy        Privacy settings and browsing data
    debugging      Chrome DevTools debugger protocol
    management     Extension and app management
    experimental   Experimental Chrome APIs

Unknown permissions not in the database are treated as medium risk.


DEVELOPMENT

```bash
git clone https://github.com/theluckystrike/crx-permission-analyzer.git
cd crx-permission-analyzer
npm install
npm test
npm run build
```

The project uses TypeScript with strict mode, Vitest for testing, and targets ES2022. Node 18 or later is required.


CONTRIBUTING

See CONTRIBUTING.md for guidelines on submitting issues and pull requests.


LICENSE

MIT. See LICENSE file for details.

---

Built by theluckystrike. Visit zovo.one for more tools.
