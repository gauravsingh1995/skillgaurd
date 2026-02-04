/**
 * Rust Analyzer
 * Pattern-based security analysis for Rust files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface RustPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Rust
const RUST_PATTERNS: RustPattern[] = [
  // CRITICAL: Unsafe & Shell Execution
  {
    name: 'unsafe block',
    severity: 'critical',
    category: 'Unsafe Code',
    description: 'Unsafe code block - bypasses Rust safety guarantees',
    pattern: /\bunsafe\s*\{/g,
  },
  {
    name: 'Command::new',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /Command::new\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'fs::write',
    severity: 'high',
    category: 'File System Write',
    description: 'Writes to files - potential data tampering',
    pattern: /fs::(write|File::create|OpenOptions)/g,
  },
  {
    name: 'fs::remove',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /fs::(remove_file|remove_dir|remove_dir_all)\s*\(/g,
  },
  {
    name: 'transmute',
    severity: 'high',
    category: 'Type Casting',
    description: 'Unsafe type transmutation - potential memory corruption',
    pattern: /\btransmute\s*</g,
  },
  {
    name: 'raw pointers',
    severity: 'high',
    category: 'Unsafe Pointers',
    description: 'Raw pointer dereferencing - potential memory unsafety',
    pattern: /\*(?:const|mut)\s+\w+/g,
  },

  // MEDIUM: Network Access
  {
    name: 'TcpStream',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network connections - potential data exfiltration',
    pattern: /TcpStream::(connect|bind)/g,
  },
  {
    name: 'reqwest',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP client - potential data exfiltration',
    pattern: /reqwest::(get|post|Client)/g,
  },
  {
    name: 'hyper',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP library - potential data exfiltration',
    pattern: /hyper::/g,
  },

  // LOW: Environment Access
  {
    name: 'env::var',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /env::var\s*\(\s*"[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },
];

export class RustAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'rust';
  readonly fileExtensions = ['.rs'];

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

    for (const pattern of RUST_PATTERNS) {
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
          language: 'rust',
        });
      }
    }

    return findings;
  }
}
