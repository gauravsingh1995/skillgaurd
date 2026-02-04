/**
 * Go Analyzer
 * Pattern-based security analysis for Go files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface GoPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Go
const GO_PATTERNS: GoPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'exec.Command',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /exec\.Command\s*\(/g,
  },
  {
    name: 'syscall.Exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'System call execution - potential arbitrary code execution',
    pattern: /syscall\.(Exec|ForkExec)\s*\(/g,
  },
  {
    name: 'eval package',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Code evaluation - potential code injection',
    pattern: /eval\./g,
  },

  // HIGH: File System Operations
  {
    name: 'os.WriteFile',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /os\.(WriteFile|Create|OpenFile)\s*\(/g,
  },
  {
    name: 'os.Remove',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /os\.(Remove|RemoveAll)\s*\(/g,
  },
  {
    name: 'os.Chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /os\.(Chmod|Chown)\s*\(/g,
  },
  {
    name: 'unsafe package',
    severity: 'high',
    category: 'Unsafe Operations',
    description: 'Uses unsafe package - bypasses type safety',
    pattern: /import\s+"unsafe"|unsafe\./g,
  },
  {
    name: 'reflect package',
    severity: 'high',
    category: 'Reflection',
    description: 'Uses reflection - potential security bypass',
    pattern: /reflect\./g,
  },

  // MEDIUM: Network Access
  {
    name: 'http.Get',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /http\.(Get|Post|Head|Put|Delete)\s*\(/g,
  },
  {
    name: 'net.Dial',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens network connections - potential data exfiltration',
    pattern: /net\.(Dial|DialTCP|DialUDP)\s*\(/g,
  },
  {
    name: 'url.Parse',
    severity: 'medium',
    category: 'Network Access',
    description: 'URL operations - review for security',
    pattern: /url\.Parse\s*\(/g,
  },

  // LOW: Environment Access
  {
    name: 'os.Getenv',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /os\.Getenv\s*\(\s*"[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },
];

export class GoAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'go';
  readonly fileExtensions = ['.go'];

  canAnalyze(filePath: string): boolean {
    return this.fileExtensions.some((ext) => filePath.endsWith(ext));
  }

  analyzeFile(filePath: string): Finding[] {
    const findings: Finding[] = [];

    let source: string;
    try {
      source = fs.readFileSync(filePath, 'utf-8');
    } catch (_error) {
      return findings;
    }

    const lines = source.split('\n');

    for (const pattern of GO_PATTERNS) {
      // Reset regex lastIndex
      pattern.pattern.lastIndex = 0;

      let match;
      while ((match = pattern.pattern.exec(source)) !== null) {
        const position = match.index;
        const lineNumber = source.substring(0, position).split('\n').length;
        const column = position - source.lastIndexOf('\n', position - 1) - 1;

        findings.push({
          file: filePath,
          line: lineNumber,
          column,
          severity: pattern.severity,
          category: pattern.category,
          description: pattern.description,
          codeSnippet: lines[lineNumber - 1]?.trim() || '',
          language: 'go',
        });
      }
    }

    return findings;
  }
}
