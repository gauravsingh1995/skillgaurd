/**
 * C/C++ Analyzer
 * Pattern-based security analysis for C/C++ files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface CppPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for C/C++
const CPP_PATTERNS: CppPattern[] = [
  // CRITICAL: Shell Execution & Unsafe Functions
  {
    name: 'system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bsystem\s*\(/g,
  },
  {
    name: 'popen',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Opens process - potential arbitrary code execution',
    pattern: /\bpopen\s*\(/g,
  },
  {
    name: 'gets',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe function - buffer overflow risk',
    pattern: /\bgets\s*\(/g,
  },
  {
    name: 'strcpy',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe string copy - buffer overflow risk',
    pattern: /\bstrcpy\s*\(/g,
  },
  {
    name: 'strcat',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe string concatenation - buffer overflow risk',
    pattern: /\bstrcat\s*\(/g,
  },
  {
    name: 'sprintf',
    severity: 'critical',
    category: 'Buffer Overflow',
    description: 'Unsafe string formatting - buffer overflow risk',
    pattern: /\bsprintf\s*\(/g,
  },

  // HIGH: Memory & File Operations
  {
    name: 'malloc without check',
    severity: 'high',
    category: 'Memory Management',
    description: 'Dynamic memory allocation - check for NULL pointer',
    pattern: /\bmalloc\s*\(/g,
  },
  {
    name: 'free',
    severity: 'high',
    category: 'Memory Management',
    description: 'Memory deallocation - check for double-free',
    pattern: /\bfree\s*\(/g,
  },
  {
    name: 'memcpy',
    severity: 'high',
    category: 'Memory Operations',
    description: 'Memory copy - potential buffer overflow',
    pattern: /\bmemcpy\s*\(/g,
  },
  {
    name: 'fopen',
    severity: 'high',
    category: 'File Operations',
    description: 'File operations - review for security',
    pattern: /\bfopen\s*\(/g,
  },
  {
    name: 'remove/unlink',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /\b(remove|unlink)\s*\(/g,
  },

  // MEDIUM: Format Strings & Network
  {
    name: 'printf with variable',
    severity: 'medium',
    category: 'Format String',
    description: 'Format string vulnerability risk',
    pattern: /\bprintf\s*\(\s*[^"']/g,
  },
  {
    name: 'socket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network socket operations - potential data exfiltration',
    pattern: /\bsocket\s*\(/g,
  },
  {
    name: 'connect',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network connection - potential data exfiltration',
    pattern: /\bconnect\s*\(/g,
  },

  // LOW: Environment Access
  {
    name: 'getenv',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /\bgetenv\s*\(/g,
  },
];

export class CppAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'cpp';
  readonly fileExtensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'];

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
    const language: Language = filePath.endsWith('.c') || filePath.endsWith('.h') ? 'c' : 'cpp';

    for (const pattern of CPP_PATTERNS) {
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
          language,
        });
      }
    }

    return findings;
  }
}
