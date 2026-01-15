/**
 * SkillGuard UI/Reporter
 * Beautiful CLI output with hacker aesthetic
 */

import chalk from 'chalk';
import boxen from 'boxen';
import figlet from 'figlet';
import ora from 'ora';
import * as path from 'path';
import { ScanResult, Finding, RiskSeverity } from './types';

/**
 * Color scheme for hacker aesthetic
 */
const colors = {
  primary: chalk.cyan,
  secondary: chalk.gray,
  success: chalk.green,
  warning: chalk.yellow,
  danger: chalk.red,
  critical: chalk.bgRed.white.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  safe: chalk.green,
  accent: chalk.magenta,
  dim: chalk.dim,
  bold: chalk.bold,
};

/**
 * Display ASCII logo
 */
export function showLogo(): void {
  console.log();
  console.log(
    colors.primary(
      figlet.textSync('SKILLGUARD', {
        font: 'ANSI Shadow',
        horizontalLayout: 'default',
      }),
    ),
  );
  console.log(colors.secondary('  ╔══════════════════════════════════════════════════════════╗'));
  console.log(
    colors.secondary('  ║') +
      colors.dim('  AI Agent Skill Security Scanner v1.0.0                   ') +
      colors.secondary('║'),
  );
  console.log(
    colors.secondary('  ║') +
      colors.dim('  Detecting security risks before they become threats      ') +
      colors.secondary('║'),
  );
  console.log(colors.secondary('  ╚══════════════════════════════════════════════════════════╝'));
  console.log();
}

/**
 * Create a spinner for scanning
 */
export function createSpinner(text: string): ora.Ora {
  return ora({
    text: colors.primary(text),
    spinner: 'dots12',
    color: 'cyan',
  });
}

/**
 * Get color for risk level
 */
function getRiskLevelColor(level: ScanResult['riskLevel']): chalk.Chalk {
  switch (level) {
    case 'safe':
      return colors.success;
    case 'low':
      return colors.low;
    case 'medium':
      return colors.warning;
    case 'high':
      return colors.danger;
    case 'critical':
      return colors.critical;
    default:
      return colors.secondary;
  }
}

/**
 * Format severity badge
 */
function formatSeverityBadge(severity: RiskSeverity): string {
  const badges: Record<RiskSeverity, string> = {
    critical: colors.critical(' CRITICAL '),
    high: colors.high('   HIGH   '),
    medium: colors.medium('  MEDIUM  '),
    low: colors.low('   LOW    '),
  };
  return badges[severity];
}

/**
 * Format file path for display (relative to target)
 */
function formatFilePath(filePath: string, basePath: string): string {
  return path.relative(basePath, filePath);
}

/**
 * Display the scan report
 */
export function showReport(result: ScanResult, targetDir: string): void {
  const levelColor = getRiskLevelColor(result.riskLevel);

  // Header with risk level
  const riskLevelText = result.riskLevel.toUpperCase();
  const header = levelColor(`
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║                    SCAN COMPLETE                             ║
  ║                    Risk Level: ${riskLevelText.padEnd(10)}                      ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
  `);

  console.log(header);

  // Summary statistics
  console.log(colors.bold('\n  📊 SCAN SUMMARY'));
  console.log(colors.secondary('  ─────────────────────────────────────────'));
  console.log(
    `  ${colors.dim('Files Scanned:')}     ${colors.primary(result.scannedFiles.toString())}`,
  );
  console.log(
    `  ${colors.dim('Scan Duration:')}     ${colors.primary(result.scanDuration + 'ms')}`,
  );
  console.log(
    `  ${colors.dim('Code Issues:')}       ${colors.primary(result.codeFindingsCount.toString())}`,
  );
  console.log(
    `  ${colors.dim('Dependency Issues:')} ${colors.primary(result.dependencyFindingsCount.toString())}`,
  );
  console.log();

  // Code findings section
  if (result.codeFindings.length > 0) {
    console.log(colors.bold('\n  🔍 CODE ANALYSIS FINDINGS'));
    console.log(colors.secondary('  ─────────────────────────────────────────'));

    // Group findings by severity
    const grouped = groupFindingsBySeverity(result.codeFindings);

    for (const severity of ['critical', 'high', 'medium', 'low'] as RiskSeverity[]) {
      const findings = grouped[severity];
      if (findings && findings.length > 0) {
        console.log(
          `\n  ${formatSeverityBadge(severity)} ${colors.bold(`(${findings.length} issue${findings.length > 1 ? 's' : ''})`)}`,
        );

        for (const finding of findings) {
          const relPath = formatFilePath(finding.file, targetDir);
          console.log();
          console.log(
            `    ${colors.accent('►')} ${colors.primary(relPath)}${colors.dim(`:${finding.line}:${finding.column}`)}`,
          );
          console.log(`      ${colors.dim('Category:')} ${finding.category}`);
          console.log(`      ${colors.dim('Issue:')} ${finding.description}`);
          console.log(
            `      ${colors.dim('Code:')} ${colors.secondary(finding.codeSnippet.substring(0, 60))}${finding.codeSnippet.length > 60 ? '...' : ''}`,
          );
        }
      }
    }
  }

  // Dependency findings section
  if (result.dependencyFindings.length > 0) {
    console.log(colors.bold('\n\n  📦 DEPENDENCY ANALYSIS FINDINGS'));
    console.log(colors.secondary('  ─────────────────────────────────────────'));

    for (const finding of result.dependencyFindings) {
      console.log();
      console.log(`    ${formatSeverityBadge(finding.severity)} ${colors.bold(finding.name)}`);
      console.log(`      ${colors.dim('Reason:')} ${finding.reason}`);
    }
  }

  // No issues found
  if (result.codeFindings.length === 0 && result.dependencyFindings.length === 0) {
    console.log(colors.success('\n  ✓ No security issues detected!'));
    console.log(colors.dim('    The scanned code appears to be safe.'));
  }

  // Risk score footer
  const scoreColor =
    result.riskScore <= 20
      ? colors.success
      : result.riskScore <= 50
        ? colors.warning
        : colors.danger;

  const scoreBar = createScoreBar(result.riskScore);

  console.log('\n');
  console.log(
    boxen(
      `${colors.bold('RISK SCORE')}\n\n` +
        `${scoreBar}\n\n` +
        `${scoreColor(result.riskScore.toString())} ${colors.dim('/ 100')}\n\n` +
        `${colors.dim('Risk Level:')} ${levelColor(riskLevelText)}`,
      {
        padding: 1,
        margin: { top: 0, bottom: 0, left: 2, right: 2 },
        borderStyle: 'round',
        borderColor: result.riskScore <= 20 ? 'green' : result.riskScore <= 50 ? 'yellow' : 'red',
        title: '[ ASSESSMENT ]',
        titleAlignment: 'center',
      },
    ),
  );

  // Recommendations
  if (result.riskScore > 0) {
    console.log(colors.bold('\n  💡 RECOMMENDATIONS'));
    console.log(colors.secondary('  ─────────────────────────────────────────'));

    if (result.codeFindings.some((f) => f.severity === 'critical')) {
      console.log(
        colors.danger(
          '  ⚠ CRITICAL: Do not install this skill. Review shell execution and eval() usage.',
        ),
      );
    }
    if (
      result.codeFindings.some(
        (f) => f.category === 'File System Write' || f.category === 'File System Delete',
      )
    ) {
      console.log(
        colors.warning('  ⚠ Review file system operations for malicious write/delete actions.'),
      );
    }
    if (result.codeFindings.some((f) => f.category === 'Network Access')) {
      console.log(
        colors.medium('  ⚠ Verify network requests are legitimate and not exfiltrating data.'),
      );
    }
    if (result.dependencyFindings.length > 0) {
      console.log(colors.warning('  ⚠ Review flagged dependencies before installing.'));
    }
  }

  console.log('\n');
}

/**
 * Create a visual score bar
 */
function createScoreBar(score: number): string {
  const width = 30;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;

  const color = score <= 20 ? colors.success : score <= 50 ? colors.warning : colors.danger;

  const bar = color('█'.repeat(filled)) + colors.dim('░'.repeat(empty));
  return `[${bar}]`;
}

/**
 * Group findings by severity
 */
function groupFindingsBySeverity(findings: Finding[]): Record<RiskSeverity, Finding[]> {
  const grouped: Record<RiskSeverity, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

/**
 * Show error message
 */
export function showError(message: string): void {
  console.log();
  console.log(
    boxen(colors.danger(`✖ ERROR\n\n${message}`), {
      padding: 1,
      margin: { top: 0, bottom: 0, left: 2, right: 2 },
      borderStyle: 'round',
      borderColor: 'red',
    }),
  );
  console.log();
}

/**
 * Show success message
 */
export function showSuccess(message: string): void {
  console.log(colors.success(`\n  ✓ ${message}\n`));
}

/**
 * Show info message
 */
export function showInfo(message: string): void {
  console.log(colors.primary(`\n  ℹ ${message}\n`));
}
