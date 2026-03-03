/**
 * Type definitions for crx-permission-analyzer
 */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface Permission {
  name: string;
  description: string;
  riskLevel: RiskLevel;
  category: PermissionCategory;
}

export type PermissionCategory = 
  | 'host' 
  | 'api' 
  | 'clipboard' 
  | 'storage' 
  | 'network' 
  | 'tab' 
  | 'bookmark' 
  | 'download' 
  | 'geolocation' 
  | 'notification' 
  | 'privacy'
  | 'debugging'
  | 'management'
  | 'experimental';

export interface PermissionAnalysis {
  manifestPath: string;
  permissions: AnalyzedPermission[];
  hostPermissions: string[];
  optionalPermissions: AnalyzedPermission[];
  riskScore: number;
  riskLevel: RiskLevel;
  dangerousCombinations: DangerousCombination[];
}

export interface AnalyzedPermission {
  name: string;
  description: string;
  riskLevel: RiskLevel;
  category: PermissionCategory;
  isOptional: boolean;
}

export interface DangerousCombination {
  permissions: string[];
  description: string;
  severity: RiskLevel;
}

export interface AnalysisOptions {
  outputFormat: 'json' | 'human';
  includeOptional: boolean;
}
