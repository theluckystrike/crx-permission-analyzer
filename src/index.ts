/**
 * CRX Permission Analyzer - Core Library
 * Analyzes Chrome extension permissions and outputs risk assessments
 */

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { resolve, extname } from 'path';
import { 
  PermissionAnalysis, 
  AnalyzedPermission, 
  DangerousCombination,
  RiskLevel,
  AnalysisOptions 
} from './types.js';
import { 
  getPermission, 
  dangerousCombinations, 
  riskWeights 
} from './permissions.js';

/**
 * Default analysis options
 */
const defaultOptions: AnalysisOptions = {
  outputFormat: 'human',
  includeOptional: true
};

/**
 * Parse a manifest.json file and extract permissions
 */
export async function parseManifest(manifestPath: string): Promise<{
  permissions: string[];
  optionalPermissions: string[];
  hostPermissions: string[];
}> {
  const content = await readFile(manifestPath, 'utf-8');
  const manifest = JSON.parse(content);
  
  const permissions: string[] = manifest.permissions || [];
  const optionalPermissions: string[] = manifest.optional_permissions || [];
  const hostPermissions: string[] = manifest.host_permissions || [];
  
  // Also check for permissions in the old format
  if (Array.isArray(manifest.permissions)) {
    // Extract host permissions from the permissions array
    const hostPerms = manifest.permissions.filter((p: string) => 
      p.includes('://') || p === '<all_urls>'
    );
    
    return {
      permissions: manifest.permissions.filter((p: string) => 
        !p.includes('://') && p !== '<all_urls>'
      ),
      optionalPermissions,
      hostPermissions: [...hostPermissions, ...hostPerms]
    };
  }
  
  return { permissions, optionalPermissions, hostPermissions };
}

/**
 * Analyze permissions and calculate risk score
 */
export function analyzePermissions(
  permissions: string[],
  optionalPermissions: string[] = [],
  hostPermissions: string[] = []
): PermissionAnalysis {
  const allPermissions = [...permissions, ...hostPermissions];
  const analyzedPermissions: AnalyzedPermission[] = [];
  
  // Analyze each permission
  for (const perm of allPermissions) {
    const dbPerm = getPermission(perm);
    if (dbPerm) {
      analyzedPermissions.push({
        name: dbPerm.name,
        description: dbPerm.description,
        riskLevel: dbPerm.riskLevel,
        category: dbPerm.category,
        isOptional: false
      });
    } else {
      // Unknown permission - treat as medium risk
      analyzedPermissions.push({
        name: perm,
        description: 'Unknown permission',
        riskLevel: 'medium',
        category: 'api',
        isOptional: false
      });
    }
  }
  
  // Analyze optional permissions
  const analyzedOptional: AnalyzedPermission[] = [];
  for (const perm of optionalPermissions) {
    const dbPerm = getPermission(perm);
    if (dbPerm) {
      analyzedOptional.push({
        name: dbPerm.name,
        description: dbPerm.description,
        riskLevel: dbPerm.riskLevel,
        category: dbPerm.category,
        isOptional: true
      });
    } else {
      analyzedOptional.push({
        name: perm,
        description: 'Unknown permission',
        riskLevel: 'medium',
        category: 'api',
        isOptional: true
      });
    }
  }
  
  // Find dangerous combinations
  const foundCombinations = findDangerousCombinations(allPermissions);
  
  // Calculate risk score
  const riskScore = calculateRiskScore(analyzedPermissions, analyzedOptional, foundCombinations);
  
  return {
    manifestPath: '',
    permissions: analyzedPermissions,
    hostPermissions,
    optionalPermissions: analyzedOptional,
    riskScore,
    riskLevel: calculateRiskLevel(riskScore),
    dangerousCombinations: foundCombinations
  };
}

/**
 * Find dangerous permission combinations
 */
function findDangerousCombinations(permissions: string[]): DangerousCombination[] {
  const found: DangerousCombination[] = [];
  const permSet = new Set(permissions.map(p => p.toLowerCase()));
  
  for (const combo of dangerousCombinations) {
    const requiredPerms = combo.permissions.map(p => p.toLowerCase());
    const hasAll = requiredPerms.every(p => permSet.has(p));
    
    if (hasAll) {
      found.push({
        permissions: combo.permissions,
        description: combo.description,
        severity: combo.severity
      });
    }
  }
  
  return found;
}

/**
 * Calculate overall risk score
 */
function calculateRiskScore(
  permissions: AnalyzedPermission[],
  optionalPermissions: AnalyzedPermission[],
  combinations: DangerousCombination[]
): number {
  let score = 0;
  
  // Add scores for each permission
  for (const perm of permissions) {
    score += riskWeights[perm.riskLevel];
  }
  
  // Add scores for optional permissions (slightly lower weight)
  for (const perm of optionalPermissions) {
    score += Math.floor(riskWeights[perm.riskLevel] * 0.5);
  }
  
  // Add scores for dangerous combinations
  for (const combo of combinations) {
    score += riskWeights[combo.severity] * 2;
  }
  
  return score;
}

/**
 * Convert risk score to risk level
 */
function calculateRiskLevel(score: number): RiskLevel {
  if (score >= 20) return 'critical';
  if (score >= 10) return 'high';
  if (score >= 5) return 'medium';
  return 'low';
}

/**
 * Main analysis function
 */
export async function analyze(
  manifestPath: string,
  options: Partial<AnalysisOptions> = {}
): Promise<PermissionAnalysis> {
  const opts = { ...defaultOptions, ...options };
  
  // Resolve the path
  const resolvedPath = resolve(manifestPath);
  
  if (!existsSync(resolvedPath)) {
    throw new Error(`Manifest file not found: ${resolvedPath}`);
  }
  
  // Check if it's a JSON file
  if (extname(resolvedPath) !== '.json') {
    throw new Error('Manifest must be a JSON file');
  }
  
  // Parse the manifest
  const { permissions, optionalPermissions, hostPermissions } = await parseManifest(resolvedPath);
  
  // Analyze permissions
  const analysis = analyzePermissions(
    permissions, 
    optionalPermissions, 
    hostPermissions
  );
  
  analysis.manifestPath = resolvedPath;
  
  // Filter optional permissions if needed
  if (!opts.includeOptional) {
    analysis.optionalPermissions = [];
  }
  
  return analysis;
}

/**
 * Format analysis as human-readable output
 */
export function formatHuman(analysis: PermissionAnalysis): string {
  const lines: string[] = [];
  
  lines.push('='.repeat(60));
  lines.push('🔒 CRX Permission Analysis Report');
  lines.push('='.repeat(60));
  lines.push('');
  lines.push(`📁 Manifest: ${analysis.manifestPath}`);
  lines.push('');
  
  // Risk summary
  const riskEmoji = {
    low: '🟢',
    medium: '🟡',
    high: '🟠',
    critical: '🔴'
  };
  
  lines.push('📊 RISK SUMMARY');
  lines.push('-'.repeat(40));
  lines.push(`  Risk Level: ${riskEmoji[analysis.riskLevel]} ${analysis.riskLevel.toUpperCase()}`);
  lines.push(`  Risk Score: ${analysis.riskScore}`);
  lines.push('');
  
  // Permissions
  if (analysis.permissions.length > 0) {
    lines.push('📌 REQUIRED PERMISSIONS');
    lines.push('-'.repeat(40));
    for (const perm of analysis.permissions) {
      lines.push(`  ${riskEmoji[perm.riskLevel]} ${perm.name}`);
      lines.push(`     ${perm.description}`);
    }
    lines.push('');
  }
  
  // Host permissions
  if (analysis.hostPermissions.length > 0) {
    lines.push('🌐 HOST PERMISSIONS');
    lines.push('-'.repeat(40));
    for (const host of analysis.hostPermissions) {
      lines.push(`  🔴 ${host}`);
    }
    lines.push('');
  }
  
  // Optional permissions
  if (analysis.optionalPermissions.length > 0) {
    lines.push('⚙️  OPTIONAL PERMISSIONS');
    lines.push('-'.repeat(40));
    for (const perm of analysis.optionalPermissions) {
      lines.push(`  ${riskEmoji[perm.riskLevel]} ${perm.name}`);
      lines.push(`     ${perm.description}`);
    }
    lines.push('');
  }
  
  // Dangerous combinations
  if (analysis.dangerousCombinations.length > 0) {
    lines.push('⚠️  DANGEROUS COMBINATIONS DETECTED');
    lines.push('-'.repeat(40));
    for (const combo of analysis.dangerousCombinations) {
      lines.push(`  ${riskEmoji[combo.severity]} ${combo.severity.toUpperCase()}`);
      lines.push(`     ${combo.description}`);
      lines.push(`     Permissions: ${combo.permissions.join(', ')}`);
    }
    lines.push('');
  }
  
  lines.push('='.repeat(60));
  
  return lines.join('\n');
}

/**
 * Format analysis as JSON output
 */
export function formatJson(analysis: PermissionAnalysis): string {
  return JSON.stringify(analysis, null, 2);
}
