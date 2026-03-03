/**
 * CRX Permission Analyzer - Core Library
 * Analyzes Chrome extension permissions and outputs risk assessments
 */
import { PermissionAnalysis, AnalysisOptions } from './types.js';
/**
 * Parse a manifest.json file and extract permissions
 */
export declare function parseManifest(manifestPath: string): Promise<{
    permissions: string[];
    optionalPermissions: string[];
    hostPermissions: string[];
}>;
/**
 * Analyze permissions and calculate risk score
 */
export declare function analyzePermissions(permissions: string[], optionalPermissions?: string[], hostPermissions?: string[]): PermissionAnalysis;
/**
 * Main analysis function
 */
export declare function analyze(manifestPath: string, options?: Partial<AnalysisOptions>): Promise<PermissionAnalysis>;
/**
 * Format analysis as human-readable output
 */
export declare function formatHuman(analysis: PermissionAnalysis): string;
/**
 * Format analysis as JSON output
 */
export declare function formatJson(analysis: PermissionAnalysis): string;
//# sourceMappingURL=index.d.ts.map