/**
 * Python Analyzer
 * Pattern-based security analysis for Python files
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';

interface PythonPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

// Security patterns for Python
const PYTHON_PATTERNS: PythonPattern[] = [
  // CRITICAL: Shell Execution
  {
    name: 'os.system',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands - potential arbitrary code execution',
    pattern: /os\.system\s*\(/g,
  },
  {
    name: 'subprocess.call',
    severity: 'critical',
    category: 'Shell Execution',
    description: 'Executes shell commands via subprocess - potential code execution',
    pattern: /subprocess\.(call|run|Popen|check_output|check_call)\s*\(/g,
  },
  {
    name: 'eval',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Evaluates arbitrary code - critical security risk',
    pattern: /\beval\s*\(/g,
  },
  {
    name: 'exec',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Executes arbitrary Python code - critical security risk',
    pattern: /\bexec\s*\(/g,
  },
  {
    name: '__import__',
    severity: 'critical',
    category: 'Dynamic Import',
    description: 'Dynamic module import - potential code injection',
    pattern: /__import__\s*\(/g,
  },
  {
    name: 'compile',
    severity: 'critical',
    category: 'Code Injection',
    description: 'Compiles Python code dynamically - potential code injection',
    pattern: /\bcompile\s*\(/g,
  },

  // HIGH: File System Operations
  {
    name: 'open with write',
    severity: 'high',
    category: 'File System Write',
    description: 'Opens file for writing - potential data tampering',
    pattern: /open\s*\([^)]*['"]w|open\s*\([^)]*['"]a/g,
  },
  {
    name: 'os.remove',
    severity: 'high',
    category: 'File System Delete',
    description: 'Deletes files - potential data destruction',
    pattern: /os\.(remove|unlink|rmdir)\s*\(/g,
  },
  {
    name: 'shutil operations',
    severity: 'high',
    category: 'File System Modification',
    description: 'File system operations - potential data tampering',
    pattern: /shutil\.(rmtree|move|copy|copytree)\s*\(/g,
  },
  {
    name: 'os.chmod',
    severity: 'high',
    category: 'File System Permissions',
    description: 'Modifies file permissions - potential privilege escalation',
    pattern: /os\.(chmod|chown)\s*\(/g,
  },
  {
    name: 'pickle.loads',
    severity: 'high',
    category: 'Deserialization',
    description: 'Deserializes Python objects - potential code execution',
    pattern: /pickle\.(loads|load)\s*\(/g,
  },

  // MEDIUM: Network Access
  {
    name: 'requests',
    severity: 'medium',
    category: 'Network Access',
    description: 'Makes HTTP requests - potential data exfiltration',
    pattern: /requests\.(get|post|put|delete|patch)\s*\(/g,
  },
  {
    name: 'urllib',
    severity: 'medium',
    category: 'Network Access',
    description: 'URL requests - potential data exfiltration',
    pattern: /urllib\.request\.(urlopen|Request)/g,
  },
  {
    name: 'socket',
    severity: 'medium',
    category: 'Network Access',
    description: 'Network socket operations - potential data exfiltration',
    pattern: /socket\.socket\s*\(/g,
  },
  {
    name: 'httplib',
    severity: 'medium',
    category: 'Network Access',
    description: 'HTTP client - potential data exfiltration',
    pattern: /http\.client\.(HTTPConnection|HTTPSConnection)/g,
  },

  // LOW: Environment Access
  {
    name: 'os.environ',
    severity: 'low',
    category: 'Environment Access',
    description: 'Accesses environment variables - potential sensitive data exposure',
    pattern: /os\.environ\s*\[['"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },
  {
    name: 'os.getenv',
    severity: 'low',
    category: 'Environment Access',
    description: 'Gets environment variables - potential sensitive data exposure',
    pattern: /os\.getenv\s*\(\s*['"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/gi,
  },
];

export class PythonAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'python';
  readonly fileExtensions = ['.py', '.pyw'];

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

    for (const pattern of PYTHON_PATTERNS) {
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
          language: 'python',
        });
      }
    }

    return findings;
  }
}
