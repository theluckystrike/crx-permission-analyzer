#!/usr/bin/env node

/**
 * CRX Permission Analyzer CLI
 */

import { analyze, formatHuman, formatJson } from './index.js';
import type { AnalysisOptions } from './types.js';

interface CliArgs {
  manifest: string;
  outputFormat: 'json' | 'human';
  includeOptional: boolean;
  help: boolean;
}

function parseArgs(args: string[]): CliArgs {
  const result: CliArgs = {
    manifest: '',
    outputFormat: 'human',
    includeOptional: true,
    help: false
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '-h':
      case '--help':
        result.help = true;
        break;
      case '-j':
      case '--json':
        result.outputFormat = 'json';
        break;
      case '-r':
      case '--human':
        result.outputFormat = 'human';
        break;
      case '--no-optional':
        result.includeOptional = false;
        break;
      default:
        if (!arg.startsWith('-') && !result.manifest) {
          result.manifest = arg;
        }
    }
  }
  
  return result;
}

function printHelp() {
  console.log(`
🔒 CRX Permission Analyzer

Analyzes Chrome extension permissions and flags dangerous combinations.

USAGE:
  crx-permission-analyzer <manifest.json> [options]

ARGUMENTS:
  manifest.json    Path to the extension's manifest.json file

OPTIONS:
  -h, --help       Show this help message
  -j, --json       Output in JSON format
  -r, --human      Output in human-readable format (default)
  --no-optional    Exclude optional permissions from analysis

EXAMPLES:
  crx-permission-analyzer manifest.json
  crx-permission-analyzer manifest.json --json
  crx-permission-analyzer manifest.json --no-optional

RISK LEVELS:
  🟢 LOW      - Minimal privacy/security impact
  🟡 MEDIUM  - Some privacy or functionality impact
  🟠 HIGH    - Significant security or privacy risk
  🔴 CRITICAL - Severe security risk, potentially malicious

MORE INFO:
  https://github.com/zovo/crx-permission-analyzer
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  
  if (args.help) {
    printHelp();
    process.exit(0);
  }
  
  if (!args.manifest) {
    console.error('Error: Please provide a path to manifest.json');
    console.error('Run: crx-permission-analyzer --help for usage information');
    process.exit(1);
  }
  
  try {
    const options: Partial<AnalysisOptions> = {
      outputFormat: args.outputFormat,
      includeOptional: args.includeOptional
    };
    
    const analysis = await analyze(args.manifest, options);
    
    if (args.outputFormat === 'json') {
      console.log(formatJson(analysis));
    } else {
      console.log(formatHuman(analysis));
    }
    
    // Exit with error code if critical or high risk
    if (analysis.riskLevel === 'critical' || analysis.riskLevel === 'high') {
      process.exit(1);
    }
    
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

main();
