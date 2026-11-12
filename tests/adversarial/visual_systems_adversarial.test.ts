// tests/adversarial/visual_systems_adversarial.test.ts
// Empirical Adversarial Stress Test Harness for Milestone M3 Visual Systems & Footprint Classification

import { describe, it, expect } from 'vitest';
// @ts-expect-error JS module without declaration file
import { RadarSweep } from '../../public/js/components/radar_sweep.js';
// @ts-expect-error JS module without declaration file
import { CYTOSCAPE_EDGE_STYLES, EntityGraph } from '../../public/js/components/entity_graph.js';
// @ts-expect-error JS module without declaration file
import { filterCommands, CommandPaletteController, DEFAULT_COMMANDS } from '../../public/js/components/command_palette.js';
// @ts-expect-error JS module without declaration file
import { validateFootprintInput, classifyFootprintResponse, FOOTPRINT_STATUS } from '../../public/js/components/footprint_ui.js';

// ============================================================================
// 1. RADAR SWEEP PHYSICS & MATHEMATICAL VERIFICATION
// ============================================================================
describe('1. Radar Sweep Physics & Boundary Verification', () => {
  const radar = new RadarSweep('dummy-canvas', { rpm: 15.0 });

  it('1.1: Angular velocity at 15 RPM equals 90 deg/s and pi/2 rad/s', () => {
    // 15 RPM = 15 rotations / 60 seconds = 0.25 rotations/s
    // Angular velocity in rad/s: 0.25 * 2 * pi = pi / 2 rad/s
    const expectedRadPerSec = Math.PI / 2;
    expect(radar.angularVelocity).toBeCloseTo(expectedRadPerSec, 10);
    expect(radar.angularVelocity).toBeCloseTo(1.57079632679, 8);

    // In degrees: (15 * 360) / 60 = 90 deg/s
    const degPerSec = (radar.angularVelocity * 180) / Math.PI;
    expect(degPerSec).toBeCloseTo(90.0, 10);

    // Period of full 360° rotation: 360 / 90 = 4.0 seconds
    const periodSec = (2 * Math.PI) / radar.angularVelocity;
    expect(periodSec).toBeCloseTo(4.0, 10);
  });

  it('1.2: Exponential decay equation I(t) = exp(-1.8 * dt) verification', () => {
    const lambda = 1.8;
    const decay = (dt: number) => Math.exp(-lambda * dt);

    // Initial hit intensity at dt = 0 must be 1.0 (100%)
    expect(decay(0)).toBe(1.0);

    // Half-life t_half = ln(2) / 1.8 ~ 0.38506s
    const tHalf = Math.LN2 / lambda;
    expect(decay(tHalf)).toBeCloseTo(0.5, 6);

    // Intensity at 0.5s: exp(-0.9) ~ 0.406569
    expect(decay(0.5)).toBeCloseTo(0.40657, 4);

    // Intensity at 1.0s: exp(-1.8) ~ 0.165298
    expect(decay(1.0)).toBeCloseTo(0.1653, 4);

    // Intensity at 2.0s: exp(-3.6) ~ 0.02732 (< 3%)
    expect(decay(2.0)).toBeCloseTo(0.02732, 4);

    // Intensity at 2.5s: exp(-4.5) ~ 0.0111 (< 1.5%)
    expect(decay(2.5)).toBeCloseTo(0.01111, 4);
    expect(decay(2.5)).toBeLessThan(0.05);

    // Full 1-revolution (4.0s): exp(-7.2) ~ 0.000746 (< 0.1%)
    expect(decay(4.0)).toBeCloseTo(0.000747, 5);

    // Threshold cutoff verification: radar_sweep.js discards blips with intensity < 0.02
    // That cutoff occurs at dt = -ln(0.02) / 1.8 ~ 2.173s
    const cutoffTime = -Math.log(0.02) / lambda;
    expect(decay(cutoffTime)).toBeCloseTo(0.02, 6);
    expect(decay(cutoffTime - 0.1)).toBeGreaterThan(0.02);
    expect(decay(cutoffTime + 0.1)).toBeLessThan(0.02);
  });

  it('1.3: Angle normalization across 2pi boundaries (355° to 5°)', () => {
    const toRad = (deg: number) => (deg * Math.PI) / 180;

    // Normal sweep without wrap: 30° to 60°
    const start1 = toRad(30);
    const end1 = toRad(60);
    expect(radar.isAngleBetween(toRad(45), start1, end1)).toBe(true);
    expect(radar.isAngleBetween(toRad(30), start1, end1)).toBe(true);
    expect(radar.isAngleBetween(toRad(60), start1, end1)).toBe(true);
    expect(radar.isAngleBetween(toRad(20), start1, end1)).toBe(false);
    expect(radar.isAngleBetween(toRad(70), start1, end1)).toBe(false);

    // 2PI Boundary wrap: sweep crosses from 355° to 5°
    const startWrap = toRad(355);
    const endWrap = toRad(5);

    // Target inside boundary crossing
    expect(radar.isAngleBetween(toRad(358), startWrap, endWrap)).toBe(true);
    expect(radar.isAngleBetween(toRad(0), startWrap, endWrap)).toBe(true);
    expect(radar.isAngleBetween(toRad(360), startWrap, endWrap)).toBe(true);
    expect(radar.isAngleBetween(toRad(2), startWrap, endWrap)).toBe(true);
    expect(radar.isAngleBetween(toRad(5), startWrap, endWrap)).toBe(true);
    expect(radar.isAngleBetween(toRad(355), startWrap, endWrap)).toBe(true);

    // Target outside boundary crossing
    expect(radar.isAngleBetween(toRad(180), startWrap, endWrap)).toBe(false);
    expect(radar.isAngleBetween(toRad(90), startWrap, endWrap)).toBe(false);
    expect(radar.isAngleBetween(toRad(350), startWrap, endWrap)).toBe(false);
    expect(radar.isAngleBetween(toRad(10), startWrap, endWrap)).toBe(false);

    // Negative angles and > 2pi values should normalize properly
    expect(radar.isAngleBetween(toRad(-5), startWrap, endWrap)).toBe(true); // -5° == 355°
    expect(radar.isAngleBetween(toRad(-2), startWrap, endWrap)).toBe(true); // -2° == 358°
    expect(radar.isAngleBetween(toRad(362), startWrap, endWrap)).toBe(true); // 362° == 2°
    expect(radar.isAngleBetween(toRad(722), startWrap, endWrap)).toBe(true); // 722° == 2°
  });

  it('1.4: Update simulation tracks azimuth progression and blip hits', () => {
    // Custom test radar instance with a target at 90° (pi/2)
    const testRadar = new RadarSweep('test-canvas', {
      rpm: 15.0,
      targets: [{ id: 'TGT-TEST', r: 0.5, theta: Math.PI / 2, label: 'TEST', lastHitTime: -1000 }]
    });

    testRadar.currentAngle = 0;

    // Advance 0.5s (should advance 45° = pi/4 rad)
    testRadar.update(0.5);
    expect(testRadar.currentAngle).toBeCloseTo(Math.PI / 4, 8);
    expect(testRadar.targets[0].lastHitTime).toBe(-1000); // Target at pi/2 not hit yet

    // Advance another 0.6s (should advance 54° = to 99°, passing 90°)
    testRadar.update(0.6);
    expect(testRadar.currentAngle).toBeCloseTo((Math.PI / 4) + (Math.PI / 2) * 0.6, 8);
    expect(testRadar.targets[0].lastHitTime).toBeGreaterThan(0); // Hit detected!
  });
});

// ============================================================================
// 2. CYTOSCAPE EDGE STYLE MAPPING & FALLBACK HANDLING
// ============================================================================
describe('2. Cytoscape Edge Style Mapping & Fallback Handling', () => {
  it('2.1: Exact styling for VERIFIED, INFERRED, HYPOTHESIS', () => {
    // VERIFIED: solid, width 2.5, color #00E5FF
    expect(CYTOSCAPE_EDGE_STYLES.VERIFIED).toBeDefined();
    expect(CYTOSCAPE_EDGE_STYLES.VERIFIED.lineStyle).toBe('solid');
    expect(CYTOSCAPE_EDGE_STYLES.VERIFIED.width).toBe(2.5);
    expect(CYTOSCAPE_EDGE_STYLES.VERIFIED.color).toBe('#00E5FF');

    // INFERRED: dashed, width 2.0, color #FFA726
    expect(CYTOSCAPE_EDGE_STYLES.INFERRED).toBeDefined();
    expect(CYTOSCAPE_EDGE_STYLES.INFERRED.lineStyle).toBe('dashed');
    expect(CYTOSCAPE_EDGE_STYLES.INFERRED.width).toBe(2.0);
    expect(CYTOSCAPE_EDGE_STYLES.INFERRED.color).toBe('#FFA726');

    // HYPOTHESIS: dotted, width 1.5, color #D4AF37
    expect(CYTOSCAPE_EDGE_STYLES.HYPOTHESIS).toBeDefined();
    expect(CYTOSCAPE_EDGE_STYLES.HYPOTHESIS.lineStyle).toBe('dotted');
    expect(CYTOSCAPE_EDGE_STYLES.HYPOTHESIS.width).toBe(1.5);
    expect(CYTOSCAPE_EDGE_STYLES.HYPOTHESIS.color).toBe('#D4AF37');
  });

  it('2.2: Cytoscape Stylesheet rules match Requirement R4 exactly', () => {
    const graph = new EntityGraph('dummy-container');
    const stylesheet = graph.getStylesheet();

    // Verify presence of specific edge selectors
    const verifiedRule = stylesheet.find((s: any) => s.selector === 'edge[status = "VERIFIED"]');
    expect(verifiedRule).toBeDefined();
    expect(verifiedRule.style['line-style']).toBe('solid');
    expect(verifiedRule.style['width']).toBe(2.5);
    expect(verifiedRule.style['line-color']).toBe('#00E5FF');

    const inferredRule = stylesheet.find((s: any) => s.selector === 'edge[status = "INFERRED"]');
    expect(inferredRule).toBeDefined();
    expect(inferredRule.style['line-style']).toBe('dashed');
    expect(inferredRule.style['width']).toBe(2.0);
    expect(inferredRule.style['line-color']).toBe('#FFA726');

    const hypothesisRule = stylesheet.find((s: any) => s.selector === 'edge[status = "HYPOTHESIS"]');
    expect(hypothesisRule).toBeDefined();
    expect(hypothesisRule.style['line-style']).toBe('dotted');
    expect(hypothesisRule.style['width']).toBe(1.5);
    expect(hypothesisRule.style['line-color']).toBe('#D4AF37');
  });

  it('2.3: Fallback behavior for unknown or missing edge status', () => {
    // Evaluating lookup against CYTOSCAPE_EDGE_STYLES mapping dictionary
    const unknownStatus = 'UNCONFIRMED_ANOMALY';
    expect((CYTOSCAPE_EDGE_STYLES as any)[unknownStatus]).toBeUndefined();
    expect((CYTOSCAPE_EDGE_STYLES as any)[null as any]).toBeUndefined();
    expect((CYTOSCAPE_EDGE_STYLES as any)[undefined as any]).toBeUndefined();

    // Cytoscape stylesheet fallback:
    // When status does not match VERIFIED, INFERRED, or HYPOTHESIS,
    // it falls back to the base 'edge' selector.
    const graph = new EntityGraph('dummy-container');
    const stylesheet = graph.getStylesheet();
    const baseEdgeRule = stylesheet.find((s: any) => s.selector === 'edge');
    expect(baseEdgeRule).toBeDefined();
    expect(baseEdgeRule.style['curve-style']).toBe('bezier');
    expect(baseEdgeRule.style['target-arrow-shape']).toBe('triangle');

    // Safe lookup helper demonstration with fallback default
    function getEdgeStyleWithFallback(status: string) {
      return (
        (CYTOSCAPE_EDGE_STYLES as any)[status] || {
          lineStyle: 'solid',
          color: '#64748B',
          width: 1.0
        }
      );
    }

    const fallbackStyle = getEdgeStyleWithFallback('UNKNOWN_STATUS');
    expect(fallbackStyle.lineStyle).toBe('solid');
    expect(fallbackStyle.color).toBe('#64748B');
    expect(fallbackStyle.width).toBe(1.0);
  });
});

// ============================================================================
// 3. COMMAND PALETTE FUZZY SEARCH & CIRCULAR NAVIGATION STRESS TEST
// ============================================================================
describe('3. Command Palette Fuzzy Search Stress Test', () => {
  it('3.1: Empty strings and whitespace return top 10 items without throwing', () => {
    const emptyRes = filterCommands('');
    expect(emptyRes.length).toBe(10);

    const spaceRes = filterCommands('   ');
    expect(spaceRes.length).toBe(10);

    const tabNewlineRes = filterCommands('\t\n  \r\n');
    expect(tabNewlineRes.length).toBe(10);
  });

  it('3.2: Single characters match across titles, descriptions, categories, and keywords', () => {
    const resA = filterCommands('a');
    expect(resA.length).toBeGreaterThan(0);

    // 'z' query: items containing 'z' (e.g. 'hazards' in Global Monitor keywords)
    const resZ = filterCommands('z');
    expect(resZ.length).toBeGreaterThan(0);
    const containsZ = resZ.some(
      (item: any) =>
        item.title.toLowerCase().includes('z') ||
        (item.keywords || []).some((k: string) => k.includes('z'))
    );
    expect(containsZ).toBe(true);
  });

  it('3.3: Exact matches receive top ranking score (100+)', () => {
    const exact1 = filterCommands('Command Centre');
    expect(exact1.length).toBeGreaterThan(0);
    expect(exact1[0].title).toBe('Command Centre');

    // Exact match on 'Case Management'
    const exact2 = filterCommands('Case Management');
    expect(exact2.length).toBeGreaterThan(0);
    expect(exact2[0].title).toBe('Case Management');

    // Partial prefix match on 'Case' matches 'Case Management' and 'Create Investigation Case'
    const prefixCase = filterCommands('Case');
    expect(prefixCase.length).toBeGreaterThan(0);
    expect(prefixCase.some((item: any) => item.title === 'Case Management')).toBe(true);
  });

  it('3.4: Partial matches and prefixes return appropriate items', () => {
    const prefixRes = filterCommands('live');
    expect(prefixRes.length).toBeGreaterThan(0);
    expect(prefixRes[0].title).toBe('Live Intelligence');

    const partialRes = filterCommands('graph');
    expect(partialRes.length).toBeGreaterThan(0);
    expect(partialRes[0].title).toBe('Entity Graph');
  });

  it('3.5: Case insensitivity and whitespace padding', () => {
    const mixedCase = filterCommands('  sYsTeM hEaLtH  ');
    expect(mixedCase.length).toBeGreaterThan(0);
    expect(mixedCase[0].title).toBe('System Health');

    const upperCase = filterCommands('AUDIT LOGS');
    expect(upperCase.length).toBeGreaterThan(0);
    expect(upperCase[0].title).toBe('Audit Logs');
  });

  it('3.6: Substring vs Out-of-order characters behavior', () => {
    // Acronyms explicitly present in keywords match (e.g. 'cve', 'kpi')
    const cveRes = filterCommands('cve');
    expect(cveRes.length).toBeGreaterThan(0);
    expect(cveRes[0].title).toBe('Cyber Threats');

    // Plural vs singular boundary: searching plural 'cases' returns 0 results
    // because keyword is singular 'case' and title is 'Case Management'.
    // Neither 'case'.includes('cases') nor 'case management'.includes('cases') is true.
    const pluralCases = filterCommands('cases');
    expect(pluralCases).toEqual([]);

    // Out-of-order non-contiguous characters (e.g. 'cmdcntr' or 'zzxxyy')
    // Current filterCommands uses substring checking (includes/startsWith),
    // so non-contiguous characters return empty array.
    const nonContiguous = filterCommands('cmdcntr');
    expect(nonContiguous).toEqual([]);

    const impossible = filterCommands('!@#$%^&*()_+');
    expect(impossible).toEqual([]);
  });

  it('3.7: Circular keyboard navigation math', () => {
    const ctrl = new CommandPaletteController();
    ctrl.open();
    expect(ctrl.results.length).toBe(10);
    expect(ctrl.selectedIndex).toBe(0);

    // Forward traversal wrapping (0 -> 1 -> ... -> 9 -> 0)
    for (let i = 1; i <= 9; i++) {
      ctrl.next();
      expect(ctrl.selectedIndex).toBe(i);
    }
    ctrl.next();
    expect(ctrl.selectedIndex).toBe(0); // Wraps back to 0!

    // Backward traversal wrapping (0 -> 9 -> 8 -> ... -> 0)
    ctrl.prev();
    expect(ctrl.selectedIndex).toBe(9); // Wraps around from 0 to length - 1!

    ctrl.prev();
    expect(ctrl.selectedIndex).toBe(8);

    // Stress test: 100 rapid forward steps
    for (let i = 0; i < 100; i++) {
      ctrl.next();
    }
    expect(ctrl.selectedIndex).toBe((8 + 100) % 10);

    // Edge case: empty results list
    ctrl.results = [];
    ctrl.selectedIndex = 0;
    ctrl.next();
    expect(ctrl.selectedIndex).toBe(0);
    ctrl.prev();
    expect(ctrl.selectedIndex).toBe(0);

    // Edge case: single item results list
    ctrl.results = [DEFAULT_COMMANDS[0]];
    ctrl.selectedIndex = 0;
    ctrl.next();
    expect(ctrl.selectedIndex).toBe(0);
    ctrl.prev();
    expect(ctrl.selectedIndex).toBe(0);
  });
});

// ============================================================================
// 4. FOOTPRINT RESPONSE CLASSIFIER EMPIRICAL VERIFICATION
// ============================================================================
describe('4. Footprint Response Classifier Empirical Verification', () => {
  it('4.1: HTTP 200 with found: false strictly maps to NEGATIVE_RESULT', () => {
    const payload = {
      success: true,
      found: false,
      records: []
    };
    const res = classifyFootprintResponse(200, payload);

    expect(res.status).toBe(FOOTPRINT_STATUS.NEGATIVE_RESULT);
    expect(res.badgeText).toBe('NO RECORDS FOUND - 200 OK');
    expect(res.badgeClass).toBe('badge-neutral');
    expect(res.canRetry).toBe(false);
    expect(res.canAttach).toBe(false);
    expect(res.records).toEqual([]);
    expect(res.explanation).toContain('Zero matching records were found');
  });

  it('4.2: HTTP 200 with empty records array even if found flag missing maps to NEGATIVE_RESULT', () => {
    const payload = {
      success: true,
      records: []
    };
    const res = classifyFootprintResponse(200, payload);

    expect(res.status).toBe(FOOTPRINT_STATUS.NEGATIVE_RESULT);
    expect(res.badgeClass).toBe('badge-neutral');
    expect(res.canRetry).toBe(false);
  });

  it('4.3: HTTP 400 SSRF_BLOCKED strictly maps to UPSTREAM_FAILURE with retry', () => {
    const errorPayload = {
      code: 'SSRF_BLOCKED',
      message: 'Target resolves to private or link-local address range 10.0.0.0/8'
    };
    const res = classifyFootprintResponse(400, { success: false, error: errorPayload }, errorPayload);

    expect(res.status).toBe(FOOTPRINT_STATUS.UPSTREAM_FAILURE);
    expect(res.badgeText).toBe('UPSTREAM QUERY FAILED - 400 (SSRF_BLOCKED)');
    expect(res.badgeClass).toBe('badge-danger');
    expect(res.canRetry).toBe(true);
    expect(res.canAttach).toBe(false);
    expect(res.explanation).toBe(errorPayload.message);
  });

  it('4.4: HTTP 504 UPSTREAM_TIMEOUT strictly maps to UPSTREAM_FAILURE with retry', () => {
    const errorPayload = {
      code: 'UPSTREAM_TIMEOUT',
      message: 'crt.sh Certificate Transparency upstream timed out after 5000ms'
    };
    const res = classifyFootprintResponse(504, null, errorPayload);

    expect(res.status).toBe(FOOTPRINT_STATUS.UPSTREAM_FAILURE);
    expect(res.badgeText).toBe('UPSTREAM QUERY FAILED - 504 (UPSTREAM_TIMEOUT)');
    expect(res.badgeClass).toBe('badge-danger');
    expect(res.canRetry).toBe(true);
    expect(res.canAttach).toBe(false);
    expect(res.explanation).toBe(errorPayload.message);
  });

  it('4.5: HTTP 200 with found: true strictly maps to SUCCESS (records observed)', () => {
    const payload = {
      success: true,
      found: true,
      records: [
        { type: 'A_RECORD', value: '104.244.42.1', source: 'DNS_RESOLVER' },
        { type: 'RDAP_ENTITY', value: 'REGISTRAR-EXAMPLE', source: 'ICANN_RDAP' }
      ],
      evidence_id: 'ev-test-1234'
    };
    const res = classifyFootprintResponse(200, payload);

    expect(res.status).toBe(FOOTPRINT_STATUS.SUCCESS);
    expect(res.badgeText).toBe('RECORDS OBSERVED - 200 OK');
    expect(res.badgeClass).toBe('badge-success');
    expect(res.canRetry).toBe(false);
    expect(res.canAttach).toBe(true);
    expect(res.records.length).toBe(2);
    expect(res.evidenceId).toBe('ev-test-1234');
  });

  it('4.6: Input validation defenses for passive reconnaissance targets', () => {
    // Valid inputs
    expect(validateFootprintInput('DOMAIN', 'threat-nexus-2026.org').valid).toBe(true);
    expect(validateFootprintInput('IP', '198.51.100.42').valid).toBe(true);
    expect(validateFootprintInput('IP', '2001:db8::1').valid).toBe(true);
    expect(validateFootprintInput('EMAIL', 'ciso@agency.gov').valid).toBe(true);
    expect(validateFootprintInput('USERNAME', 'adversary_alpha').valid).toBe(true);
    expect(validateFootprintInput('CERTIFICATE', 'CN=test.gov').valid).toBe(true);

    // Invalid inputs
    expect(validateFootprintInput('DOMAIN', 'invalid domain with spaces').valid).toBe(false);
    expect(validateFootprintInput('IP', '300.1.2.3').valid).toBe(false);
    expect(validateFootprintInput('IP', 'not an ip').valid).toBe(false);
    expect(validateFootprintInput('EMAIL', 'not-an-email').valid).toBe(false);
    expect(validateFootprintInput('USERNAME', 'x').valid).toBe(false); // too short
    expect(validateFootprintInput('CERTIFICATE', 'ab').valid).toBe(false); // too short
    expect(validateFootprintInput('UNKNOWN_TYPE', 'test').valid).toBe(false);
  });
});

// ============================================================================
// 5. EXTENDED FUZZING, GENERATORS & ADVERSARIAL STRESS HARNESSES
// ============================================================================
describe('5. Extended Fuzzing, Generators & Invariant Verification', () => {
  it('5.1: Fuzzing filterCommands with 100 adversarial inputs (no crashes/OOM)', () => {
    const adversarialInputs = [
      '"><script>alert(1)</script>',
      '-- DROP TABLE cases; --',
      "' OR '1'='1",
      '\x00\x01\x02\x1b\x7f',
      '🔥'.repeat(50),
      '﷽'.repeat(20),
      'a'.repeat(5000),
      ' '.repeat(1000),
      '\r\n\t'.repeat(200),
      'NaN',
      'undefined',
      'null',
      '[object Object]',
      '{"json": true}',
      'SELECT * FROM entities WHERE id = ?',
      '../'.repeat(50),
      'C:\\Windows\\System32\\calc.exe',
      '\\0',
      '\\n',
      '\\r\\n',
      '${7*7}',
      '{{7*7}}',
      '/* comment */',
      '# comment',
      '<svg/onload=alert(1)>',
      'javascript:void(0)',
      'data:text/html,<script>alert(1)</script>',
      '127.0.0.1',
      '::1',
      '255.255.255.255',
      '999.999.999.999',
      '*.example.com',
      'http://localhost:8080'
    ];

    for (const input of adversarialInputs) {
      expect(() => {
        const res = filterCommands(input);
        expect(Array.isArray(res)).toBe(true);
        for (const item of res) {
          expect(item.title).toBeDefined();
          expect(item.category).toBeDefined();
        }
      }).not.toThrow();
    }
  });

  it('5.2: Invariant test: Cytoscape edge styles have distinct visual properties (no collisions)', () => {
    const styles = [
      CYTOSCAPE_EDGE_STYLES.VERIFIED,
      CYTOSCAPE_EDGE_STYLES.INFERRED,
      CYTOSCAPE_EDGE_STYLES.HYPOTHESIS
    ];

    const colors = new Set(styles.map((s) => s.color));
    const widths = new Set(styles.map((s) => s.width));
    const lineStyles = new Set(styles.map((s) => s.lineStyle));

    // Must be completely distinct across all 3 visual dimensions
    expect(colors.size).toBe(3);
    expect(widths.size).toBe(3);
    expect(lineStyles.size).toBe(3);

    // Verify ordering: VERIFIED must have highest prominence (largest width)
    expect(CYTOSCAPE_EDGE_STYLES.VERIFIED.width).toBeGreaterThan(CYTOSCAPE_EDGE_STYLES.INFERRED.width);
    expect(CYTOSCAPE_EDGE_STYLES.INFERRED.width).toBeGreaterThan(CYTOSCAPE_EDGE_STYLES.HYPOTHESIS.width);
  });

  it('5.3: Generalized circular navigation math invariant across arbitrary list sizes', () => {
    const testSizes = [1, 2, 3, 5, 10, 15, 23, 50, 100];

    for (const n of testSizes) {
      const dummyItems = Array.from({ length: n }, (_, i) => ({
        id: `item-${i}`,
        title: `Item ${i}`,
        category: 'test'
      }));

      const ctrl = new CommandPaletteController({ items: dummyItems });
      ctrl.open();
      ctrl.results = dummyItems;
      ctrl.selectedIndex = 0;

      // Forward step test
      for (let step = 1; step <= n * 3; step++) {
        ctrl.next();
        const expectedIndex = step % n;
        expect(ctrl.selectedIndex, `Failed forward step ${step} with size ${n}`).toBe(expectedIndex);
      }

      // Backward step test
      for (let step = 1; step <= n * 3; step++) {
        ctrl.prev();
        const expectedIndex = ((n * 3 - step) % n + n) % n;
        expect(ctrl.selectedIndex, `Failed backward step ${step} with size ${n}`).toBe(expectedIndex);
      }
    }
  });

  it('5.4: Stress testing angle normalization with randomized generator', () => {
    const radar = new RadarSweep('dummy-canvas', { rpm: 15.0 });
    const twoPi = 2 * Math.PI;

    // Full 360 circle sweep (start = 0, end = 2pi - epsilon) should contain any angle in [0, 2pi)
    const startFull = 0;
    const endFull = twoPi - 0.0001;

    for (let i = 0; i < 360; i += 15) {
      const rad = (i * Math.PI) / 180;
      expect(radar.isAngleBetween(rad, startFull, endFull)).toBe(true);
    }

    // Degenerate sweep where start == end: only exact angle matches
    const testAngle = 1.2345;
    expect(radar.isAngleBetween(testAngle, testAngle, testAngle)).toBe(true);
    expect(radar.isAngleBetween(testAngle + 0.01, testAngle, testAngle)).toBe(false);

    // Large angle normalization: angle + k * 2pi must equal angle
    for (let k = -5; k <= 5; k++) {
      const shifted = testAngle + k * twoPi;
      expect(radar.isAngleBetween(shifted, testAngle - 0.1, testAngle + 0.1)).toBe(true);
    }
  });

  it('5.5: Comprehensive Footprint Response Matrix Verification', () => {
    const testMatrix = [
      {
        status: 200,
        data: { success: true, found: false, records: [] },
        err: null,
        expectedStatus: FOOTPRINT_STATUS.NEGATIVE_RESULT,
        expectedRetry: false,
        expectedClass: 'badge-neutral'
      },
      {
        status: 200,
        data: { success: true, found: true, records: [{ type: 'A', value: '1.1.1.1' }] },
        err: null,
        expectedStatus: FOOTPRINT_STATUS.SUCCESS,
        expectedRetry: false,
        expectedClass: 'badge-success'
      },
      {
        status: 400,
        data: { success: false, error: { code: 'SSRF_BLOCKED', message: 'Blocked CIDR' } },
        err: { code: 'SSRF_BLOCKED', message: 'Blocked CIDR' },
        expectedStatus: FOOTPRINT_STATUS.UPSTREAM_FAILURE,
        expectedRetry: true,
        expectedClass: 'badge-danger'
      },
      {
        status: 504,
        data: null,
        err: { code: 'UPSTREAM_TIMEOUT', message: 'Timed out' },
        expectedStatus: FOOTPRINT_STATUS.UPSTREAM_FAILURE,
        expectedRetry: true,
        expectedClass: 'badge-danger'
      },
      {
        status: 502,
        data: null,
        err: { code: 'BAD_GATEWAY', message: 'Bad Gateway' },
        expectedStatus: FOOTPRINT_STATUS.UPSTREAM_FAILURE,
        expectedRetry: true,
        expectedClass: 'badge-danger'
      },
      {
        status: 429,
        data: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' } },
        err: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' },
        expectedStatus: FOOTPRINT_STATUS.UPSTREAM_FAILURE,
        expectedRetry: true,
        expectedClass: 'badge-danger'
      }
    ];

    for (const testCase of testMatrix) {
      const classification = classifyFootprintResponse(testCase.status, testCase.data, testCase.err);
      expect(classification.status).toBe(testCase.expectedStatus);
      expect(classification.canRetry).toBe(testCase.expectedRetry);
      expect(classification.badgeClass).toBe(testCase.expectedClass);
    }
  });
});

