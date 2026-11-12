// tests/integration/api.test.ts
// Integration tests for EYE OF DHARMA REST API endpoints using supertest

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';

describe('EYE OF DHARMA REST API Integration', () => {
  let db: Database.Database;
  let app: import('express').Express;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    db.pragma('busy_timeout = 5000');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  describe('Health & Status Endpoints', () => {
    it('GET /api/v1/health should return UP status and database telemetry', async () => {
      const res = await request(app).get('/api/v1/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('UP');
      expect(res.body.db.status).toBe('CONNECTED');
      expect(res.body.db.engine).toBe('SQLite-WAL');
    });

    it('GET /api/v1/system/status should return memory, table counts, and synthetic counts', async () => {
      const res = await request(app).get('/api/v1/system/status');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.tables.cases).toBe(2);
      expect(res.body.synthetic_counts.evidence_ledger).toBe(2);
    });

    it('GET /api/v1/auth/csrf should set cookie and return csrfToken', async () => {
      const res = await request(app).get('/api/v1/auth/csrf');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.csrfToken).toBeDefined();
    });
  });

  describe('Cases Management & Dossier Endpoints', () => {
    it('GET /api/v1/cases should list seeded cases', async () => {
      const res = await request(app).get('/api/v1/cases');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.items.length).toBe(2);
      expect(res.body.total).toBe(2);
    });

    it('POST /api/v1/cases should create a new case', async () => {
      const newCase = {
        title: 'Operation Dark Sun Intrusion',
        description: 'Targeted spearphishing campaign against defense contractors',
        priority: 'HIGH',
        lead_analyst: 'Analyst Harper',
        tags: ['SPEARPHISHING', 'DEFENSE', 'MALWARE']
      };

      const res = await request(app)
        .post('/api/v1/cases')
        .set('x-bypass-csrf', 'true')
        .send(newCase);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toMatch(/^case-/);
      expect(res.body.data.title).toBe(newCase.title);
      expect(res.body.data.tags).toEqual(newCase.tags);
    });

    it('GET /api/v1/cases/:id should return single case details and metrics', async () => {
      const res = await request(app).get('/api/v1/cases/case-00000000-0000-0000-0000-000000000001');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.title).toContain('Operation Arctic Phoenix');
      expect(res.body.data.metrics.evidenceCount).toBe(2);
      expect(res.body.data.metrics.entityCount).toBe(4);
    });

    it('PATCH /api/v1/cases/:id should update case status and priority', async () => {
      const res = await request(app)
        .patch('/api/v1/cases/case-00000000-0000-0000-0000-000000000001')
        .set('x-bypass-csrf', 'true')
        .send({ status: 'IN_PROGRESS', priority: 'HIGH' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('IN_PROGRESS');
      expect(res.body.data.priority).toBe('HIGH');
    });

    it('GET /api/v1/cases/:id/graph should return Cytoscape.js nodes and edges', async () => {
      const res = await request(app).get('/api/v1/cases/case-00000000-0000-0000-0000-000000000001/graph');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.elements.nodes.length).toBeGreaterThan(0);
      expect(res.body.elements.edges.length).toBeGreaterThan(0);
      expect(res.body.elements.nodes[0].data.id).toBeDefined();
    });

    it('GET /api/v1/cases/:id/timeline should return sorted chronological timeline items', async () => {
      const res = await request(app).get('/api/v1/cases/case-00000000-0000-0000-0000-000000000001/timeline');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.items.length).toBeGreaterThan(0);
    });

    it('POST /api/v1/cases/:id/export should export case dossier in HTML, CSV, and JSON', async () => {
      // JSON format
      const resJson = await request(app)
        .post('/api/v1/cases/case-00000000-0000-0000-0000-000000000001/export')
        .set('x-bypass-csrf', 'true')
        .send({ format: 'json' });
      expect(resJson.status).toBe(200);
      expect(resJson.body.dossier).toBeDefined();

      // HTML format
      const resHtml = await request(app)
        .post('/api/v1/cases/case-00000000-0000-0000-0000-000000000001/export')
        .set('x-bypass-csrf', 'true')
        .send({ format: 'html' });
      expect(resHtml.status).toBe(200);
      expect(resHtml.text).toContain('[EYE OF DHARMA] Case Dossier');

      // CSV format
      const resCsv = await request(app)
        .post('/api/v1/cases/case-00000000-0000-0000-0000-000000000001/export')
        .set('x-bypass-csrf', 'true')
        .send({ format: 'csv' });
      expect(resCsv.status).toBe(200);
      expect(resCsv.text).toContain('content_fingerprint');
    });
  });

  describe('Evidence Ledger Ingestion & Cryptographic Provenance', () => {
    it('POST /api/v1/evidence should ingest raw payload and compute SHA-256 fingerprint', async () => {
      const raw = JSON.stringify({ ioc: 'malicious-domain.xyz', type: 'C2' });
      const payload = {
        source_url: 'https://cisa.gov/alerts/test',
        source_type: 'CISA_ADVISORY',
        source_title: 'CISA Test Alert',
        raw_content: raw,
        confidence_score: 0.85
      };

      const res = await request(app)
        .post('/api/v1/evidence')
        .set('x-bypass-csrf', 'true')
        .send(payload);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toMatch(/^ev-/);
      expect(res.body.data.content_fingerprint).toHaveLength(64);
      expect(res.body.data.immutable_lock).toBe(1);
    });

    it('GET /api/v1/evidence/:id should retrieve evidence record', async () => {
      const res = await request(app).get('/api/v1/evidence/ev-00000000-0000-0000-0000-000000000001');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.source_title).toContain('AA26-081A');
    });
  });

  describe('Entities & Relationships Endpoints', () => {
    it('POST /api/v1/entities should create entity with risk score', async () => {
      const entity = {
        name: 'Cobalt Strike C2 Host',
        type: 'IP_ADDRESS',
        value: '198.51.100.25',
        risk_score: 92
      };

      const res = await request(app)
        .post('/api/v1/entities')
        .set('x-bypass-csrf', 'true')
        .send(entity);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.risk_score).toBe(92);
    });

    it('GET /api/v1/entities/:id/graph should return neighborhood graph', async () => {
      const res = await request(app).get('/api/v1/entities/ent-00000000-0000-0000-0000-000000000001/graph');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.elements.nodes.length).toBeGreaterThan(0);
    });

    it('POST /api/v1/relationships should create link between two entities', async () => {
      const rel = {
        source_entity_id: 'ent-00000000-0000-0000-0000-000000000002',
        target_entity_id: 'ent-00000000-0000-0000-0000-000000000004',
        relation_type: 'ASSOCIATED_WITH',
        confidence: 0.88,
        status: 'VERIFIED'
      };

      const res = await request(app)
        .post('/api/v1/relationships')
        .set('x-bypass-csrf', 'true')
        .send(rel);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.relation_type).toBe('ASSOCIATED_WITH');
    });
  });

  describe('Threat Indicators & Watchlists Endpoints', () => {
    it('GET /api/v1/threats should return active threat indicators', async () => {
      const res = await request(app).get('/api/v1/threats?is_active=true');
      expect(res.status).toBe(200);
      expect(res.body.items.length).toBeGreaterThan(0);
    });

    it('POST /api/v1/watchlists and PATCH /api/v1/watchlists/:id should manage watchlists', async () => {
      const wl = {
        name: 'New C2 Pattern',
        target_type: 'DOMAIN',
        pattern: '*.evil-domain.cc',
        alert_severity: 'HIGH'
      };

      const createRes = await request(app)
        .post('/api/v1/watchlists')
        .set('x-bypass-csrf', 'true')
        .send(wl);

      expect(createRes.status).toBe(201);
      const id = createRes.body.data.id;

      const toggleRes = await request(app)
        .patch(`/api/v1/watchlists/${id}`)
        .set('x-bypass-csrf', 'true')
        .send({ is_active: false });

      expect(toggleRes.status).toBe(200);
      expect(toggleRes.body.data.is_active).toBe(0);
    });
  });

  describe('Terminal Allowlisted Command Console', () => {
    it('POST /api/v1/terminal/exec should execute allowlisted help command', async () => {
      const res = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'help' });

      expect(res.status).toBe(200);
      expect(res.body.output).toContain('=== EYE OF DHARMA ALLOWLISTED TERMINAL CONSOLE ===');
    });

    it('POST /api/v1/terminal/exec should execute status and cases list commands', async () => {
      const resStatus = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'status' });
      expect(resStatus.body.output).toContain('[EOD OPERATIONAL STATUS]');

      const resCases = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'cases list' });
      expect(resCases.body.output).toContain('Operation Arctic Phoenix');
    });

    it('POST /api/v1/terminal/exec should reject unauthorized commands safely without shell execution', async () => {
      const res = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'cat /etc/passwd' });

      expect(res.status).toBe(200);
      expect(res.body.output).toContain('Command not recognized');
    });
  });

  describe('Audit Events Log', () => {
    it('GET /api/v1/audit should return system and mutation audit trail', async () => {
      const res = await request(app).get('/api/v1/audit');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.items.length).toBeGreaterThan(0);
    });
  });

  describe('Footprint & Multi-Agent Run Endpoints', () => {
    it('POST /api/v1/investigate/footprint should execute passive lookup and record evidence if case_id provided', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'DOMAIN',
          target: 'localhost.test',
          confirm_passive: true,
          case_id: 'case-00000000-0000-0000-0000-000000000001'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.passive).toBe(true);
    });

    it('POST /api/v1/agents/dispatch should accept agent run in PLANNED state', async () => {
      const res = await request(app)
        .post('/api/v1/agents/dispatch')
        .set('x-bypass-csrf', 'true')
        .send({
          case_id: 'case-00000000-0000-0000-0000-000000000001',
          agent_name: 'DHARMA',
          goal: 'Perform automated evidence triage'
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('PLANNED');
    });
  });
});
