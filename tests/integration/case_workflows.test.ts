// tests/integration/case_workflows.test.ts
// Integration tests for Milestone M4 Case Management Workflows, Evidence Linking, Notes, Graph, Timeline & Custody

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';

describe('M4 Integration: Case Management Full Lifecycle', () => {
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

  it('CASE-WORKFLOW-1: Creates, lists, filters, and retrieves case dossier with metrics', async () => {
    // 1. Create Case
    const createRes = await request(app)
      .post('/api/v1/cases')
      .set('x-bypass-csrf', 'true')
      .send({
        title: 'Operation Midnight Trident',
        description: 'Tracking offshore C2 infrastructure targeting maritime SCADA networks',
        priority: 'HIGH',
        tlp: 'TLP:AMBER',
        classification: 'RESTRICTED',
        lead_analyst: 'Lead Analyst Vance',
        tags: ['MARITIME', 'SCADA', 'APT-44']
      });

    expect(createRes.status).toBe(201);
    expect(createRes.body.success).toBe(true);
    const caseId = createRes.body.data.id;
    expect(caseId).toMatch(/^case-/);
    expect(createRes.body.data.tlp).toBe('TLP:AMBER');
    expect(createRes.body.data.classification).toBe('RESTRICTED');

    // 2. Filter cases by TLP and status
    const filterRes = await request(app).get('/api/v1/cases?tlp=TLP:AMBER&status=OPEN');
    expect(filterRes.status).toBe(200);
    expect(filterRes.body.items.some((c: any) => c.id === caseId)).toBe(true);

    // 3. Search cases by full-text query
    const searchRes = await request(app).get('/api/v1/cases?q=Trident');
    expect(searchRes.status).toBe(200);
    expect(searchRes.body.items.length).toBeGreaterThanOrEqual(1);
    expect(searchRes.body.items[0].title).toContain('Midnight Trident');

    // 4. Retrieve single case dossier with metrics
    const getRes = await request(app).get(`/api/v1/cases/${caseId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.data.metrics).toBeDefined();
    expect(getRes.body.data.metrics.evidenceCount).toBe(0);
    expect(getRes.body.data.metrics.notesCount).toBe(0);

    // 5. Update case status to CLOSED -> sets closed_at
    const patchRes = await request(app)
      .patch(`/api/v1/cases/${caseId}`)
      .set('x-bypass-csrf', 'true')
      .send({ status: 'CLOSED', summary: 'Remediation completed; C2 node neutralized.' });

    expect(patchRes.status).toBe(200);
    expect(patchRes.body.data.status).toBe('CLOSED');
    expect(patchRes.body.data.closed_at).toBeDefined();
  });

  it('CASE-WORKFLOW-2: Soft-deletes case to preserve evidence ledger immutability', async () => {
    // 1. Create case with attached evidence
    const createCase = await request(app)
      .post('/api/v1/cases')
      .set('x-bypass-csrf', 'true')
      .send({ title: 'Temporary Investigation Case', priority: 'LOW' });
    const caseId = createCase.body.data.id;

    const addEvidence = await request(app)
      .post(`/api/v1/cases/${caseId}/evidence`)
      .set('x-bypass-csrf', 'true')
      .send({
        source_url: 'https://cisa.gov/advisories/aa26-090a',
        source_type: 'CISA_ADVISORY',
        source_title: 'Advisory AA26-090A',
        raw_content: '{"threat":"ransomware"}',
        confidence_score: 0.9
      });
    expect(addEvidence.status).toBe(201);
    const evidenceId = addEvidence.body.data.id;

    // 2. DELETE case -> soft-deletes as ARCHIVED
    const deleteRes = await request(app)
      .delete(`/api/v1/cases/${caseId}`)
      .set('x-bypass-csrf', 'true');

    expect(deleteRes.status).toBe(200);
    expect(deleteRes.body.soft_deleted).toBe(true);
    expect(deleteRes.body.status).toBe('ARCHIVED');

    // 3. Evidence remains completely intact in evidence_ledger
    const evidenceRow = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(evidenceId) as any;
    expect(evidenceRow).toBeDefined();
    expect(evidenceRow.case_id).toBe(caseId);

    // 4. Audit trail records CASE_ARCHIVED
    const auditRow = db.prepare("SELECT * FROM audit_events WHERE entity_id = ? AND action = 'CASE_ARCHIVED'").get(caseId);
    expect(auditRow).toBeDefined();
  });
});

describe('M4 Integration: Evidence Ingestion and Junction Attachment', () => {
  let db: Database.Database;
  let app: any;
  const testCaseId = 'case-00000000-0000-0000-0000-000000000001';

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

  it('EVID-WORKFLOW-1: Attaches existing evidence record via case_evidence junction', async () => {
    // 1. Create an independent unlinked evidence record in evidence_ledger
    const standaloneEvidenceId = 'ev-standalone-001';
    db.prepare(`
      INSERT INTO evidence_ledger (
        id, source_url, source_type, source_title, content_fingerprint,
        raw_content, verification_status, recorded_by, immutable_lock
      ) VALUES (
        ?, 'https://crt.sh/?q=global-feed.org', 'CRT_SH', 'Certificate for global-feed.org',
        '${'c'.repeat(64)}', '{"common_name":"global-feed.org"}', 'Observed', 'SYSTEM', 1
      )
    `).run(standaloneEvidenceId);

    // 2. Attach standalone evidence to test case via POST /cases/:id/evidence/attach
    const attachRes = await request(app)
      .post(`/api/v1/cases/${testCaseId}/evidence/attach`)
      .set('x-bypass-csrf', 'true')
      .send({
        evidence_id: standaloneEvidenceId,
        notes: 'Attached during forensic triage'
      });

    expect(attachRes.status).toBe(200);
    expect(attachRes.body.attached).toBe(true);
    expect(attachRes.body.evidence_id).toBe(standaloneEvidenceId);

    // 3. Verify junction table row created
    const junction = db.prepare('SELECT * FROM case_evidence WHERE case_id = ? AND evidence_id = ?')
      .get(testCaseId, standaloneEvidenceId) as any;
    expect(junction).toBeDefined();
    expect(junction.notes).toBe('Attached during forensic triage');

    // 4. Verify evidence_ledger row was NOT updated (preserving immutability)
    const ev = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(standaloneEvidenceId) as any;
    expect(ev.immutable_lock).toBe(1);

    // 5. GET /cases/:id/evidence returns both seeded and junction-attached evidence
    const listRes = await request(app).get(`/api/v1/cases/${testCaseId}/evidence`);
    expect(listRes.status).toBe(200);
    expect(listRes.body.items.some((item: any) => item.id === standaloneEvidenceId)).toBe(true);
  });
});

describe('M4 Integration: Append-Only Analyst Notes & Versioning', () => {
  let db: Database.Database;
  let app: any;
  const testCaseId = 'case-00000000-0000-0000-0000-000000000001';

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

  it('NOTE-WORKFLOW-1: Appends original note (v1) and amendment note (v2) with audit trail', async () => {
    // 1. Post original note (v1)
    const note1Res = await request(app)
      .post(`/api/v1/cases/${testCaseId}/notes`)
      .set('x-bypass-csrf', 'true')
      .send({
        author: 'Investigator Vance',
        content: 'Initial scan identified C2 listener active on 195.140.228.17.',
        tags: ['C2', 'INITIAL_FINDING']
      });

    expect(note1Res.status).toBe(201);
    expect(note1Res.body.data.version).toBe(1);
    expect(note1Res.body.data.content_hash).toBeDefined();
    const note1Id = note1Res.body.data.id;

    // 2. Post amendment note (v2) referencing parent_note_id
    const note2Res = await request(app)
      .post(`/api/v1/cases/${testCaseId}/notes`)
      .set('x-bypass-csrf', 'true')
      .send({
        author: 'Investigator Vance',
        content: 'Correction: C2 listener was migrating to alternate DNS hostname.',
        parent_note_id: note1Id,
        tags: ['AMENDMENT', 'DNS']
      });

    expect(note2Res.status).toBe(201);
    expect(note2Res.body.data.version).toBe(2);
    expect(note2Res.body.data.parent_note_id).toBe(note1Id);

    // 3. GET /cases/:id/notes retrieves both notes sorted chronologically
    const getNotes = await request(app).get(`/api/v1/cases/${testCaseId}/notes`);
    expect(getNotes.status).toBe(200);
    expect(getNotes.body.items.length).toBe(2);
    expect(getNotes.body.items[0].version).toBe(1);
    expect(getNotes.body.items[1].version).toBe(2);

    // 4. Verify audit_events recorded NOTE_ADDED and NOTE_AMENDED
    const audits = db.prepare("SELECT * FROM audit_events WHERE action IN ('NOTE_ADDED', 'NOTE_AMENDED')").all() as any[];
    expect(audits.length).toBe(2);
  });
});

describe('M4 Integration: Graph Serialization, Timeline Synthesis & Custody', () => {
  let db: Database.Database;
  let app: any;
  const testCaseId = 'case-00000000-0000-0000-0000-000000000001';

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

  it('GRAPH-WORKFLOW-1: GET /cases/:id/graph guarantees referential integrity for all edge endpoints', async () => {
    const res = await request(app).get(`/api/v1/cases/${testCaseId}/graph`);
    expect(res.status).toBe(200);
    expect(res.body.nodes).toBeDefined();
    expect(res.body.edges).toBeDefined();
    expect(res.body.elements.nodes).toBeDefined();

    const nodeIds = new Set(res.body.nodes.map((n: any) => n.data.id));
    for (const edge of res.body.edges) {
      expect(nodeIds.has(edge.data.source)).toBe(true);
      expect(nodeIds.has(edge.data.target)).toBe(true);
      expect(['VERIFIED', 'INFERRED', 'HYPOTHESIS']).toContain(edge.data.status);
    }
  });

  it('TIMELINE-WORKFLOW-1: GET /cases/:id/timeline returns 4 swimlanes with normalized Zulu UTC', async () => {
    // Add a note and an entity so swimlanes are populated
    await request(app)
      .post(`/api/v1/cases/${testCaseId}/notes`)
      .set('x-bypass-csrf', 'true')
      .send({ author: 'Analyst', content: 'Timeline milestone note' });

    const res = await request(app).get(`/api/v1/cases/${testCaseId}/timeline`);
    expect(res.status).toBe(200);
    expect(res.body.swimlanes).toBeDefined();
    expect(res.body.swimlanes.EVIDENCE).toBeDefined();
    expect(res.body.swimlanes.THREATS).toBeDefined();
    expect(res.body.swimlanes.AGENT_RUNS).toBeDefined();
    expect(res.body.swimlanes.ANALYST_NOTES).toBeDefined();

    for (const item of res.body.items) {
      expect(item.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(['EVIDENCE', 'THREATS', 'AGENT_RUNS', 'ANALYST_NOTES']).toContain(item.swimlane);
    }
  });

  it('CUSTODY-WORKFLOW-1: GET /cases/:id/custody returns full chronological audit chain with SHA-256 target hashes', async () => {
    const res = await request(app).get(`/api/v1/cases/${testCaseId}/custody`);
    expect(res.status).toBe(200);
    expect(res.body.custody_chain).toBeDefined();
    expect(res.body.custody_chain.length).toBeGreaterThan(0);

    for (const entry of res.body.custody_chain) {
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(entry.target_hash).toMatch(/^[a-f0-9]{64}$/);
      expect(entry.actor).toBeDefined();
      expect(entry.action).toBeDefined();
    }
  });
});

describe('M4 Integration: Digital Footprint Passive Recon & Dual Persistence', () => {
  let db: Database.Database;
  let app: any;
  const testCaseId = 'case-00000000-0000-0000-0000-000000000001';

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

  it('FOOTPRINT-WORKFLOW-1: Confirmed negative domain returns 200 OK with found: false', async () => {
    const res = await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'DOMAIN',
        target: 'confirmed-nxdomain-nonexistent.invalid',
        confirm_passive: true
      });

    expect(res.status).toBe(200);
    expect(res.body.found).toBe(false);
    expect(res.body.records).toEqual([]);
    expect(res.body.evidence_id).toBeNull();
  });

  it('FOOTPRINT-WORKFLOW-2: Dual persistence caches in feed_records and commits immutable evidence', async () => {
    const res = await request(app)
      .post('/api/v1/investigate/footprint')
      .set('x-bypass-csrf', 'true')
      .send({
        query_type: 'EMAIL',
        target: 'analyst@nordic-power.net',
        confirm_passive: true,
        case_id: testCaseId
      });

    expect(res.status).toBe(200);
    expect(res.body.found).toBe(true);
    expect(res.body.evidence_id).toBeDefined();

    // 1. Verify cached in feed_records
    const feed = db.prepare('SELECT * FROM feed_records WHERE external_id LIKE ?')
      .get('%analyst@nordic-power.net%') as any;
    expect(feed).toBeDefined();

    // 2. Verify immutable lock in evidence_ledger
    const ev = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(res.body.evidence_id) as any;
    expect(ev.immutable_lock).toBe(1);
  });

  it('FOOTPRINT-WORKFLOW-3: Rejects SSRF loopback and link-local probes', async () => {
    const forbiddenIps = ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1'];
    for (const ip of forbiddenIps) {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'IP', target: ip, confirm_passive: true });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
    }
  });
});
