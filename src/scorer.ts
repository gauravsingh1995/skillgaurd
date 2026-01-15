/**
 * SkillGuard Risk Scorer
 * Calculates overall risk score based on findings
 */

import { Finding, DependencyFinding, ScanResult, RiskSeverity } from './types';

/**
 * Risk score weights by category
 */
const CATEGORY_WEIGHTS: Record<string, number> = {
  'Shell Execution': 50,
  'Code Injection': 50,
  'File System Write': 30,
  'File System Delete': 30,
  'File System Permissions': 25,
  'Network Access': 20,
  'Environment Access': 10,
};

/**
 * Risk score weights by severity
 */
const SEVERITY_WEIGHTS: Record<RiskSeverity, number> = {
  critical: 50,
  high: 30,
  medium: 15,
  low: 5,
};

/**
 * Dependency threat weights
 */
const DEPENDENCY_SEVERITY_WEIGHTS: Record<RiskSeverity, number> = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
};

/**
 * Calculate risk score from findings
 * Score ranges from 0 (safe) to 100 (critical)
 */
export function calculateRiskScore(
  codeFindings: Finding[],
  dependencyFindings: DependencyFinding[],
): number {
  let score = 0;

  // Score code findings
  for (const finding of codeFindings) {
    // Use category weight if available, otherwise use severity weight
    const categoryWeight = CATEGORY_WEIGHTS[finding.category];
    const severityWeight = SEVERITY_WEIGHTS[finding.severity];

    // Take the higher of the two weights
    score += Math.max(categoryWeight || 0, severityWeight);
  }

  // Score dependency findings
  for (const finding of dependencyFindings) {
    score += DEPENDENCY_SEVERITY_WEIGHTS[finding.severity];
  }

  // Cap the score at 100
  return Math.min(score, 100);
}

/**
 * Determine risk level from score
 */
export function getRiskLevel(score: number): ScanResult['riskLevel'] {
  if (score === 0) return 'safe';
  if (score <= 20) return 'low';
  if (score <= 50) return 'medium';
  if (score <= 75) return 'high';
  return 'critical';
}

/**
 * Get risk statistics for reporting
 */
export function getRiskStats(
  codeFindings: Finding[],
  dependencyFindings: DependencyFinding[],
): {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
} {
  const counts = {
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
  };

  for (const finding of codeFindings) {
    switch (finding.severity) {
      case 'critical':
        counts.criticalCount++;
        break;
      case 'high':
        counts.highCount++;
        break;
      case 'medium':
        counts.mediumCount++;
        break;
      case 'low':
        counts.lowCount++;
        break;
    }
  }

  for (const finding of dependencyFindings) {
    switch (finding.severity) {
      case 'critical':
        counts.criticalCount++;
        break;
      case 'high':
        counts.highCount++;
        break;
      case 'medium':
        counts.mediumCount++;
        break;
      case 'low':
        counts.lowCount++;
        break;
    }
  }

  return counts;
}
