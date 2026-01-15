/**
 * SkillGuard Type Definitions
 * Core types for security scanning and risk assessment
 */

export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  file: string;
  line: number;
  column: number;
  severity: RiskSeverity;
  category: string;
  description: string;
  codeSnippet: string;
}

export interface DependencyFinding {
  name: string;
  severity: RiskSeverity;
  reason: string;
}

export interface ScanResult {
  codeFindingsCount: number;
  dependencyFindingsCount: number;
  codeFindings: Finding[];
  dependencyFindings: DependencyFinding[];
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  scannedFiles: number;
  scanDuration: number;
}

export interface RiskPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  nodeType: string;
  matcher: (node: any, ancestors?: any[]) => boolean;
}

export interface ThreatEntry {
  name: string;
  reason: string;
  severity: RiskSeverity;
}
