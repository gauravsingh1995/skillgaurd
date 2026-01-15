import { analyzeFile } from '../analyzer';
import * as fs from 'fs';

// Mock fs to avoid reading actual files
jest.mock('fs');

describe('Analyzer', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should detect shell execution', () => {
    const mockSource = `
      const { exec } = require('child_process');
      exec('rm -rf /');
    `;
    (fs.readFileSync as jest.Mock).mockReturnValue(mockSource);
    // Mock files existence if needed, but analyzeFile currently only does readFileSync in the try block

    const findings = analyzeFile('dummy.js');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe('Shell Execution');
  });

  it('should return empty findings for safe code', () => {
    const mockSource = `
      const a = 1;
      console.log(a);
    `;
    (fs.readFileSync as jest.Mock).mockReturnValue(mockSource);

    const findings = analyzeFile('safe.js');
    expect(findings).toHaveLength(0);
  });
});
