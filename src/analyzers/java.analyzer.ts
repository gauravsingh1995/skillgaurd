/**
 * Java Analyzer
 * Pattern-based security analysis for Java files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface JavaPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Java
const JAVA_PATTERNS: JavaPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'Runtime.exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/g,
  },
  {
    name: 'ProcessBuilder',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Creates processes - potential arbitrary code execution',
    pattern: /new\s+ProcessBuilder\s*\(/g,
  },
  {
    name: 'Script evaluation',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates scripts dynamically - potential code injection',
    pattern: /ScriptEngine.*\.eval\s*\(/g,
  },
  {
    name: 'Reflection',
    severity: 'critical',
    category: 'Reflection',
    description: 'Uses reflection - potential security bypass',
    pattern: /Class\.forName\s*\(|Method\.invoke\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'File write',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /new\s+FileWriter\s*\(|new\s+FileOutputStream\s*\(|Files\.write\s*\(/g,
  },
  {
    name: 'File delete',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /\.delete\s*\(\)|Files\.delete\s*\(/g,
  },
  {
    name: 'Deserialization',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes objects - potential code execution',
    pattern: /ObjectInputStream|readObject\s*\(/g,
  },
  {
    name: 'JNDI lookup',
    severity: 'high',
    category: 'JNDI Injection',
    description: 'JNDI lookup - potential remote code execution (Log4Shell)',
    pattern: /InitialContext.*\.lookup\s*\(/g,
  },

  // MEDIUM: Network Access
  {
    name: 'URL connection',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens network connections - potential data exfiltration',
    pattern: /new\s+URL\s*\(.*\.openConnection\s*\(/g,
  },
  {
    name: 'HTTP client',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP client operations - potential data exfiltration',
    pattern: /HttpClient|HttpURLConnection/g,
  },
  {
    name: 'Socket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Creates network sockets - potential data exfiltration',
    pattern: /new\s+Socket\s*\(|new\s+ServerSocket\s*\(/g,
  },

  // LOW: SQL Injection Risk
  {
    name: 'SQL Statement',
    severity: 'low',
    category: 'SQL Operations',
    description: 'SQL statement execution - review for SQL injection',
    pattern: /Statement.*\.execute(Query|Update)\s*\(/g,
  },
  {
    name: 'System properties',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses system properties - potential sensitive data exposure',
    pattern: /System\.getProperty\s*\(/g,
  },
];

export class JavaAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'java';
  readonly fileExtensions = ['.java'];

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

    for (const pattern of JAVA_PATTERNS) {
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
          language: 'java',
        });
      }
    }

    return findings;
  }
}
