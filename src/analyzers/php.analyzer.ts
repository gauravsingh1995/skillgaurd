/**
 * PHP Analyzer
 * Pattern-based security analysis for PHP files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface PHPPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for PHP
const PHP_PATTERNS: PHPPattern[] = [
  // CRITICAL: Shell Execution & Code Injection
  {
    name: 'exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bexec\s*\(/g,
  },
  {
    name: 'shell_exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bshell_exec\s*\(/g,
  },
  {
    name: 'system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bsystem\s*\(/g,
  },
  {
    name: 'passthru',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bpassthru\s*\(/g,
  },
  {
    name: 'eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates arbitrary PHP code - critical security risk',
    pattern: /\beval\s*\(/g,
  },
  {
    name: 'assert',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Can execute code - potential code injection',
    pattern: /\bassert\s*\(/g,
  },
  {
    name: 'preg_replace /e',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Deprecated /e modifier allows code execution',
    pattern: /preg_replace\s*\([^)]*['"]\/[^'"]*e/g,
  },
  {
    name: 'create_function',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Creates functions dynamically - potential code injection',
    pattern: /\bcreate_function\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'file_put_contents',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /\bfile_put_contents\s*\(/g,
  },
  {
    name: 'fwrite',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /\bfwrite\s*\(/g,
  },
  {
    name: 'unlink',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /\bunlink\s*\(/g,
  },
  {
    name: 'rmdir',
    severity: 'high',
    category: 'File System Delete',
    description: 'Removes directories - potential data destruction',
    pattern: /\brmdir\s*\(/g,
  },
  {
    name: 'chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /\bchmod\s*\(/g,
  },
  {
    name: 'unserialize',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes data - potential code execution',
    pattern: /\bunserialize\s*\(/g,
  },
  {
    name: 'include/require',
    severity: 'high',
    category: 'File Inclusion',
    description: 'Includes files - potential remote file inclusion',
    pattern: /\b(include|require|include_once|require_once)\s*\(/g,
  },

  // MEDIUM: Network Access & SQL
  {
    name: 'curl_exec',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /\bcurl_exec\s*\(/g,
  },
  {
    name: 'file_get_contents URL',
    severity: 'medium',
    category: 'Network Access',
    description: 'Fetches remote content - potential data exfiltration',
    pattern: /\bfile_get_contents\s*\(\s*['"]https?:/g,
  },
  {
    name: 'fsockopen',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens network socket - potential data exfiltration',
    pattern: /\bfsockopen\s*\(/g,
  },
  {
    name: 'mysql_query',
    severity: 'medium',
    category: 'SQL Operations',
    description: 'SQL query - review for SQL injection',
    pattern: /\bmysql_query\s*\(/g,
  },
  {
    name: 'mysqli_query',
    severity: 'medium',
    category: 'SQL Operations',
    description: 'SQL query - review for SQL injection',
    pattern: /\bmysqli_query\s*\(/g,
  },

  // LOW: Environment & Globals
  {
    name: '$_SERVER access',
    severity: 'low',
    category: 'Server Variables',
    description: 'Accesses server variables - review for security',
    pattern: /\$_SERVER/g,
  },
  {
    name: 'getenv',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /\bgetenv\s*\(/g,
  },
];

export class PHPAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'php';
  readonly fileExtensions = ['.php', '.phtml'];

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

    for (const pattern of PHP_PATTERNS) {
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
          language: 'php',
        });
      }
    }

    return findings;
  }
}
