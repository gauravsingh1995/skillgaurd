/**
 * Ruby Analyzer
 * Pattern-based security analysis for Ruby files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface RubyPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Ruby
const RUBY_PATTERNS: RubyPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bsystem\s*\(/g,
  },
  {
    name: 'exec',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /\bexec\s*\(/g,
  },
  {
    name: 'backticks',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Shell command execution via backticks - potential code execution',
    pattern: /`[^`]*`/g,
  },
  {
    name: 'eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates arbitrary code - critical security risk',
    pattern: /\beval\s*\(/g,
  },
  {
    name: 'instance_eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Instance evaluation - potential code injection',
    pattern: /\.instance_eval\s*\(/g,
  },
  {
    name: 'class_eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Class evaluation - potential code injection',
    pattern: /\.class_eval\s*\(/g,
  },
  {
    name: 'send',
    severity: 'critical',
    category: 'Dynamic Method Call',
    description: 'Dynamic method invocation - potential security bypass',
    pattern: /\.send\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'File.write',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /File\.(write|open)\s*\(/g,
  },
  {
    name: 'File.delete',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /File\.(delete|unlink)\s*\(/g,
  },
  {
    name: 'FileUtils',
    severity: 'high',
    category: 'File System Modification',
    description: 'File system operations - potential data tampering',
    pattern: /FileUtils\.(rm|rm_rf|mv|cp)\s*\(/g,
  },
  {
    name: 'File.chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /File\.(chmod|chown)\s*\(/g,
  },
  {
    name: 'Marshal.load',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes objects - potential code execution',
    pattern: /Marshal\.load\s*\(/g,
  },

  // MEDIUM: Network Access
  {
    name: 'Net::HTTP',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /Net::HTTP\.(get|post|start)/g,
  },
  {
    name: 'open-uri',
    severity: 'medium',
    category: 'Network Access',
    description: 'Opens URIs - potential data exfiltration',
    pattern: /require\s+['"]open-uri['"]|URI\.open/g,
  },
  {
    name: 'TCPSocket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Creates network sockets - potential data exfiltration',
    pattern: /TCPSocket\.new\s*\(/g,
  },

  // LOW: Environment Access
  {
    name: 'ENV access',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /ENV\s*\[\s*['"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },
];

export class RubyAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'ruby';
  readonly fileExtensions = ['.rb'];

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

    for (const pattern of RUBY_PATTERNS) {
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
          language: 'ruby',
        });
      }
    }

    return findings;
  }
}
