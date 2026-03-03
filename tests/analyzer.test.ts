import { describe, it, expect } from 'vitest';
import { analyze, formatHuman, formatJson } from '../src/index.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('Permission Analyzer', () => {
  const testDir = join(tmpdir(), 'crx-permission-analyzer-test');
  
  beforeAll(() => {
    mkdirSync(testDir, { recursive: true });
  });
  
  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });
  
  describe('analyze', () => {
    it('should analyze a basic manifest with minimal permissions', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Test Extension',
        version: '1.0.0',
        permissions: ['storage', 'alarms']
      };
      
      const manifestPath = join(testDir, 'minimal-manifest.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath);
      
      expect(result.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThan(5);
      expect(result.dangerousCombinations).toHaveLength(0);
    });
    
    it('should analyze a manifest with high-risk permissions', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'High Risk Extension',
        version: '1.0.0',
        permissions: ['cookies', 'webRequest', 'tabs', 'scripting']
      };
      
      const manifestPath = join(testDir, 'high-risk-manifest.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath);
      
      // Risk level is at least high or critical due to multiple high-risk permissions
      expect(['high', 'critical']).toContain(result.riskLevel);
      expect(result.riskScore).toBeGreaterThan(10);
    });
    
    it('should analyze a manifest with host permissions', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Host Permission Extension',
        version: '1.0.0',
        permissions: ['storage'],
        host_permissions: ['<all_urls>']
      };
      
      const manifestPath = join(testDir, 'host-manifest.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath);
      
      expect(result.hostPermissions).toContain('<all_urls>');
      // storage (low=1) + <all_urls> (critical=10) = 11 = high
      expect(['high', 'critical']).toContain(result.riskLevel);
    });
    
    it('should detect dangerous permission combinations', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Dangerous Extension',
        version: '1.0.0',
        permissions: ['<all_urls>', 'webRequest', 'cookies']
      };
      
      const manifestPath = join(testDir, 'dangerous-manifest.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath);
      
      expect(result.dangerousCombinations.length).toBeGreaterThan(0);
      expect(result.dangerousCombinations.some(c => 
        c.permissions.includes('<all_urls>') && c.permissions.includes('webRequest')
      )).toBe(true);
    });
    
    it('should analyze optional permissions', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Optional Perms Extension',
        version: '1.0.0',
        permissions: ['storage'],
        optional_permissions: ['geolocation', 'notifications']
      };
      
      const manifestPath = join(testDir, 'optional-manifest.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath);
      
      expect(result.optionalPermissions.length).toBe(2);
    });
    
    it('should exclude optional permissions when specified', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Optional Perms Extension',
        version: '1.0.0',
        permissions: ['storage'],
        optional_permissions: ['geolocation']
      };
      
      const manifestPath = join(testDir, 'optional-filtered-manifest.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath, { includeOptional: false });
      
      expect(result.optionalPermissions).toHaveLength(0);
    });
    
    it('should throw error for non-existent manifest', async () => {
      await expect(analyze('/nonexistent/path/manifest.json')).rejects.toThrow();
    });
    
    it('should throw error for non-JSON file', async () => {
      const txtPath = join(testDir, 'not-json.txt');
      writeFileSync(txtPath, 'not json');
      
      await expect(analyze(txtPath)).rejects.toThrow('Manifest must be a JSON file');
    });
  });
  
  describe('formatHuman', () => {
    it('should format analysis as human-readable text', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Test Extension',
        version: '1.0.0',
        permissions: ['storage']
      };
      
      const manifestPath = join(testDir, 'format-test.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath);
      const output = formatHuman(result);
      
      expect(output).toContain('CRX Permission Analysis Report');
      expect(output).toContain('Risk Level');
      expect(output).toContain('storage');
    });
  });
  
  describe('formatJson', () => {
    it('should format analysis as JSON', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Test Extension',
        version: '1.0.0',
        permissions: ['storage']
      };
      
      const manifestPath = join(testDir, 'format-json-test.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      
      const result = await analyze(manifestPath);
      const output = formatJson(result);
      
      const parsed = JSON.parse(output);
      expect(parsed.riskLevel).toBe('low');
      expect(parsed.permissions).toBeDefined();
    });
  });
});
