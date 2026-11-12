// tests/integration/connectors.test.ts
// Integration Tests for OSINT Connectors, Database Persistence, Immutability & API Routes

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase, computeSha256 } from '../../server/db/seed.js';
import { ConnectorManager } from '../../server/connectors/manager.js';
import type { NormalizedEvidenceItem } from '../../server/connectors/base.js';

describe('OSINT Connectors Integration', () => {
  let db: Database.Database;
  let app: import('express').Express;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    db.pragma('recursive_triggers = ON');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  describe('SQLite Persistence & Immutability Enforcement', () => {
    it('should persist crt.sh normalized items to evidence_ledger and feed_records', () => {
      const caseRow = db.prepare('SELECT id FROM cases LIMIT 1').get() as { id: string };
      const rawPayload = JSON.stringify({
        id: 9948271,
        common_name: 'vpn.nordic-power.net',
        issuer_name: "C=US, O=Let's Encrypt, CN=R3"
      });
      const hash = computeSha256(rawPayload);
      const evidId = 'ev-test-crt-01';

      // Insert into evidence_ledger
      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status,
          confidence_score, immutable_lock
        ) VALUES (?, ?, 'https://crt.sh/?q=nordic-power.net&output=json', 'CRT_SH', 'Certificate Search', ?, ?, 'Observed', 0.95, 1)
      `).run(evidId, caseRow.id, hash, rawPayload);

      // Insert into feed_records
      db.prepare(`
        INSERT INTO feed_records (
          id, feed_name, title, category, severity, source_url, published_at, payload
        ) VALUES ('feed-crt-01', 'CRT_SH', 'Cert: vpn.nordic-power.net', 'CERTIFICATE', 'INFO', 'https://crt.sh/?q=nordic-power.net', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?)
      `).run(rawPayload);

      const savedEvidence = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(evidId) as any;
      expect(savedEvidence).toBeDefined();
      expect(savedEvidence.source_type).toBe('CRT_SH');
      expect(savedEvidence.verification_status).toBe('Observed');
      expect(savedEvidence.immutable_lock).toBe(1);

      const savedFeed = db.prepare('SELECT * FROM feed_records WHERE id = ?').get('feed-crt-01') as any;
      expect(savedFeed).toBeDefined();
      expect(savedFeed.category).toBe('CERTIFICATE');
    });

    it('should strictly enforce evidence_ledger immutability triggers (prohibit UPDATE & DELETE)', () => {
      const caseRow = db.prepare('SELECT id FROM cases LIMIT 1').get() as { id: string };
      const rawPayload = JSON.stringify({ test: 'immutability' });
      const hash = computeSha256(rawPayload);
      const evidId = 'ev-immutable-test-01';

      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status,
          confidence_score, immutable_lock
        ) VALUES (?, ?, 'https://test.source/data', 'DNS_RECORD', 'DNS Test', ?, ?, 'Observed', 0.90, 1)
      `).run(evidId, caseRow.id, hash, rawPayload);

      // Verify UPDATE is blocked by SQLite trigger
      expect(() => {
        db.prepare("UPDATE evidence_ledger SET notes = 'altered' WHERE id = ?").run(evidId);
      }).toThrow(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      // Verify DELETE is blocked by SQLite trigger
      expect(() => {
        db.prepare('DELETE FROM evidence_ledger WHERE id = ?').run(evidId);
      }).toThrow(/EVIDENCE_IMMUTABILITY_VIOLATION/);
    });

    it('should skip duplicate evidence insertions without tripping replace trigger in ConnectorManager.persistItems', () => {
      const manager = new ConnectorManager(db);

      const items: NormalizedEvidenceItem[] = [
        {
          id: 'test:item-001',
          caseId: null,
          sourceConnectorId: 'usgs',
          sourceName: 'USGS Earthquakes',
          sourceUrl: 'https://earthquake.usgs.gov/test',
          sourceType: 'USGS_EARTHQUAKE',
          feedCategory: 'EARTHQUAKE',
          severity: 'MEDIUM',
          title: 'M 4.5 Test Quake',
          summary: 'Test summary',
          publishedAt: '2026-10-28T12:00:00Z',
          retrievedAt: '2026-10-28T12:01:00Z',
          verificationStatus: 'Observed',
          confidenceScore: 0.9,
          contentHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          rawPayload: { quake: 1 }
        }
      ];

      // First run: inserts
      const res1 = manager.persistItems(items);
      expect(res1.evidenceRecordsInserted).toBe(1);
      expect(res1.evidenceDuplicatesSkipped).toBe(0);
      expect(res1.feedRecordsUpdated).toBe(1);

      // Second run: should safely skip duplicate without throwing trigger error!
      const res2 = manager.persistItems(items);
      expect(res2.evidenceRecordsInserted).toBe(0);
      expect(res2.evidenceDuplicatesSkipped).toBe(1);
      expect(res2.feedRecordsUpdated).toBe(1); // feed_records upserted
    });
  });

  describe('API Endpoints: /api/v1/feeds/refresh and /feeds/health', () => {
    it('POST /api/v1/feeds/refresh should return refreshed status telemetry', async () => {
      const res = await request(app)
        .post('/api/v1/feeds/refresh')
        .set('x-bypass-csrf', 'true')
        .send({ feed_names: ['CRT_SH', 'DNS_RDAP'] });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.refreshed).toContain('CRT_SH');
      expect(res.body.refreshed).toContain('DNS_RDAP');
      expect(res.body.count).toBe(2);
      expect(res.body.errors).toEqual([]);
    });

    it('GET /api/v1/feeds/health should return health records of registered connectors', async () => {
      const res = await request(app).get('/api/v1/feeds/health');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.connectors).toBeDefined();
      expect(typeof res.body.connectors).toBe('object');
    });
  });

  describe('API Endpoints: /api/v1/investigate/footprint', () => {
    it('should require confirm_passive: true and reject unconfirmed queries', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'DOMAIN', target: 'example.com' }); // missing confirm_passive

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should block private and link-local IPs via SSRF filter', async () => {
      const privateIps = ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1'];
      for (const ip of privateIps) {
        const res = await request(app)
          .post('/api/v1/investigate/footprint')
          .set('x-bypass-csrf', 'true')
          .send({ query_type: 'IP', target: ip, confirm_passive: true });

        expect(res.status).toBe(400);
        expect(res.body.success).toBe(false);
        expect(res.body.error.code).toBe('SSRF_BLOCKED');
      }
    });

    it('should distinguish negative results (non-resolving domain) from errors', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'DOMAIN', target: 'nxdomain-test-nonexistent.internal.invalid', confirm_passive: true });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.found).toBe(false);
      expect(res.body.records).toEqual([]);
    });

    it('should link evidence to case_id when provided in query', async () => {
      const caseRow = db.prepare('SELECT id FROM cases LIMIT 1').get() as { id: string };

      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'EMAIL',
          target: 'analyst@nordic-power.net',
          confirm_passive: true,
          case_id: caseRow.id
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.found).toBe(true);
      expect(res.body.evidence_id).toBeDefined();

      const evid = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(res.body.evidence_id) as any;
      expect(evid).toBeDefined();
      expect(evid.case_id).toBe(caseRow.id);
      expect(evid.immutable_lock).toBe(1);
    });
  });
});
