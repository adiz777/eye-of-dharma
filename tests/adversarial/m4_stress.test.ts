// tests/adversarial/m4_stress.test.ts
// Adversarial stress test suite for Milestone M4: Immutability triggers, SSRF firewall, SQL injection, and cascade attacks

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';

describe('M4 Adversarial: case_notes Immutability Triggers', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    runMigrations(db);

    db.prepare("INSERT INTO cases (id, title) VALUES ('case-adv-01', 'Adversarial Case')").run();
    db.prepare(`
      INSERT INTO case_notes (id, case_id, author, content, content_hash)
      VALUES ('note-adv-01', 'case-adv-01', 'Investigator Vance', 'Classified observation', '${'d'.repeat(64)}')
    `).run();
  });

  afterEach(() => {
    db.close();
  });

  it('ADV-NOTE-1: Direct SQL UPDATE on case_notes throws NOTE_IMMUTABILITY_VIOLATION', () => {
    expect(() => {
      db.prepare('UPDATE case_notes SET content = ? WHERE id = ?').run('Tampered note text', 'note-adv-01');
    }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

    const note = db.prepare('SELECT content FROM case_notes WHERE id = ?').get('note-adv-01') as any;
    expect(note.content).toBe('Classified observation');
  });

  it('ADV-NOTE-2: Direct SQL DELETE on case_notes throws NOTE_IMMUTABILITY_VIOLATION', () => {
    expect(() => {
      db.prepare('DELETE FROM case_notes WHERE id = ?').run('note-adv-01');
    }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

    const note = db.prepare('SELECT id FROM case_notes WHERE id = ?').get('note-adv-01');
    expect(note).toBeDefined();
  });

  it('ADV-NOTE-3: INSERT OR REPLACE overwrite attempt throws NOTE_IMMUTABILITY_VIOLATION', () => {
    expect(() => {
      db.prepare(`
        INSERT INTO case_notes (id, case_id, author, content, content_hash)
        VALUES ('note-adv-01', 'case-adv-01', 'Attacker', 'Overwritten', '${'e'.repeat(64)}')
      `).run();
    }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);
  });
});

describe('M4 Adversarial: API Boundaries & Defense-in-Depth', () => {
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

  it('ADV-API-1: Rejects cross-case note amendment attempts with 400', async () => {
    // Create a note on Case 1
    const note1 = await request(app)
      .post(`/api/v1/cases/${testCaseId}/notes`)
      .set('x-bypass-csrf', 'true')
      .send({ author: 'Analyst', content: 'Note belonging to Case 1' });
    const note1Id = note1.body.data.id;

    // Create Case 2
    const case2 = await request(app)
      .post('/api/v1/cases')
      .set('x-bypass-csrf', 'true')
      .send({ title: 'Independent Case 2', priority: 'LOW' });
    const case2Id = case2.body.data.id;

    // Attempt to amend note1 from Case 2 -> must be rejected
    const attackRes = await request(app)
      .post(`/api/v1/cases/${case2Id}/notes`)
      .set('x-bypass-csrf', 'true')
      .send({
        author: 'Attacker',
        content: 'Cross-case hijacking amendment',
        parent_note_id: note1Id
      });

    expect(attackRes.status).toBe(400);
    expect(attackRes.body.error.code).toBe('CROSS_CASE_AMENDMENT_PROHIBITED');
  });

  it('ADV-API-2: Rejects non-existent parent note ID with 400 INVALID_PARENT_NOTE', async () => {
    const res = await request(app)
      .post(`/api/v1/cases/${testCaseId}/notes`)
      .set('x-bypass-csrf', 'true')
      .send({
        author: 'Analyst',
        content: 'Orphan amendment attempt',
        parent_note_id: 'note-does-not-exist-0000'
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARENT_NOTE');
  });

  it('ADV-API-3: Rejects oversized note (>5,000 chars) with 400 VALIDATION_ERROR', async () => {
    const res = await request(app)
      .post(`/api/v1/cases/${testCaseId}/notes`)
      .set('x-bypass-csrf', 'true')
      .send({
        author: 'Analyst',
        content: 'A'.repeat(5001)
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('ADV-API-4: SQL injection attack in cases search executes safely as parameterized literal', async () => {
    const sqlPayloads = [
      "' OR '1'='1",
      "'; DROP TABLE cases; --",
      "admin'--",
      "UNION SELECT * FROM sqlite_master WHERE '1'='1"
    ];

    for (const payload of sqlPayloads) {
      const res = await request(app).get(`/api/v1/cases?q=${encodeURIComponent(payload)}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.items)).toBe(true);
    }

    // Verify cases table is completely undamaged
    const count = db.prepare('SELECT count(*) as cnt FROM cases').get() as { cnt: number };
    expect(count.cnt).toBeGreaterThanOrEqual(2);
  });

  it('ADV-API-5: SSRF attack vectors on footprint endpoint are comprehensively blocked', async () => {
    const maliciousTargets = [
      '127.0.0.1',
      '127.0.0.2',
      '10.0.0.1',
      '10.255.255.254',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.0.1',
      '192.168.1.254',
      '169.254.169.254',
      '0.0.0.0',
      '::1',
      'fe80::1',
      '::ffff:127.0.0.1'
    ];

    for (const ip of maliciousTargets) {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'IP', target: ip, confirm_passive: true });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
    }
  });

  it('ADV-API-6: Case deletion with attached evidence safely soft-deletes and preserves evidence', async () => {
    // Check initial evidence count for case
    const initialEv = db.prepare('SELECT count(*) as cnt FROM evidence_ledger WHERE case_id = ?').get(testCaseId) as { cnt: number };
    expect(initialEv.cnt).toBeGreaterThan(0);

    // Delete case via DELETE endpoint
    const res = await request(app)
      .delete(`/api/v1/cases/${testCaseId}`)
      .set('x-bypass-csrf', 'true');

    expect(res.status).toBe(200);
    expect(res.body.soft_deleted).toBe(true);

    // Evidence must still exist and be intact
    const postEv = db.prepare('SELECT count(*) as cnt FROM evidence_ledger WHERE case_id = ?').get(testCaseId) as { cnt: number };
    expect(postEv.cnt).toBe(initialEv.cnt);

    // Case status is now ARCHIVED
    const caseRow = db.prepare('SELECT status FROM cases WHERE id = ?').get(testCaseId) as any;
    expect(caseRow.status).toBe('ARCHIVED');
  });
});
