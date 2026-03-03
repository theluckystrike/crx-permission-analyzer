/**
 * Permission database with descriptions and risk assessments
 */
import type { Permission, RiskLevel } from './types.js';
export declare const permissionDatabase: Record<string, Permission>;
/**
 * Dangerous permission combinations that should be flagged
 */
export declare const dangerousCombinations: {
    permissions: string[];
    description: string;
    severity: RiskLevel;
}[];
/**
 * Risk score weights for calculations
 */
export declare const riskWeights: {
    readonly critical: 10;
    readonly high: 5;
    readonly medium: 2;
    readonly low: 1;
};
/**
 * Get a permission from the database
 */
export declare function getPermission(name: string): Permission | undefined;
/**
 * Check if a permission exists in the database
 */
export declare function hasPermission(name: string): boolean;
//# sourceMappingURL=permissions.d.ts.map