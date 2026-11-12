// tests/adversarial/m4_challenger_verification.test.ts
// Empirical Adversarial Stress Test Suite for Milestone M4
// Challenger: challenger_m4_1 (critic, specialist)
// Scope: Immutability Triggers, Hard Deletion & Cascade Protection, Boundary & Injection Attacks, Concurrency & Idempotency

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';
// @ts-expect-error JS module without declaration file
import { renderSafeMarkdown, formatSha256Pill } from '../../public/js/components/case_workspace.js';

describe('CHALLENGER M4: Adversarial Stress & Verification Suite', () => {
  let db: Database.Database;
  let app: any;
  const testCaseId = 'case-00000000-0000-0000-0000-000000000001';
  const testEvidenceId = 'ev-00000000-0000-0000-0000-000000000001';

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

  // =========================================================================
  // SCENARIO 1: case_notes Immutability Attacks
  // =========================================================================
  describe('Scenario 1: case_notes Immutability Attack Vectors', () => {
    const noteId = 'note-chal-001';

    beforeEach(() => {
      db.prepare(`
        INSERT INTO case_notes (id, case_id, author, content, content_hash, version)
        VALUES (?, ?, 'Lead Investigator', 'Initial immutable observation', ?, 1)
      `).run(noteId, testCaseId, 'f'.repeat(64));
    });

    it('SCEN-1.1: Direct SQL UPDATE on content throws NOTE_IMMUTABILITY_VIOLATION', () => {
      expect(() => {
        db.prepare('UPDATE case_notes SET content = ? WHERE id = ?').run('Hacked content', noteId);
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

      const row = db.prepare('SELECT content FROM case_notes WHERE id = ?').get(noteId) as any;
      expect(row.content).toBe('Initial immutable observation');
    });

    it('SCEN-1.2: Direct SQL UPDATE on author, tags, or version throws NOTE_IMMUTABILITY_VIOLATION', () => {
      expect(() => {
        db.prepare('UPDATE case_notes SET author = ? WHERE id = ?').run('Impostor', noteId);
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

      expect(() => {
        db.prepare('UPDATE case_notes SET tags = ? WHERE id = ?').run('["tampered"]', noteId);
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

      expect(() => {
        db.prepare('UPDATE case_notes SET version = 99 WHERE id = ?').run(noteId);
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);
    });

    it('SCEN-1.3: Direct SQL DELETE throws NOTE_IMMUTABILITY_VIOLATION', () => {
      expect(() => {
        db.prepare('DELETE FROM case_notes WHERE id = ?').run(noteId);
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

      const row = db.prepare('SELECT id FROM case_notes WHERE id = ?').get(noteId);
      expect(row).toBeDefined();
    });

    it('SCEN-1.4: Unconditional DELETE FROM case_notes throws NOTE_IMMUTABILITY_VIOLATION', () => {
      expect(() => {
        db.prepare('DELETE FROM case_notes').run();
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

      const count = db.prepare('SELECT count(*) as cnt FROM case_notes').get() as { cnt: number };
      expect(count.cnt).toBeGreaterThan(0);
    });

    it('SCEN-1.5: INSERT OR REPLACE overwrite attempt triggers immutability violation', () => {
      expect(() => {
        db.prepare(`
          INSERT OR REPLACE INTO case_notes (id, case_id, author, content, content_hash, version)
          VALUES (?, ?, 'Attacker', 'Overwritten note content', ?, 2)
        `).run(noteId, testCaseId, 'a'.repeat(64));
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);

      const row = db.prepare('SELECT content, author FROM case_notes WHERE id = ?').get(noteId) as any;
      expect(row.author).toBe('Lead Investigator');
      expect(row.content).toBe('Initial immutable observation');
    });

    it('SCEN-1.6: Duplicate primary key INSERT triggers replace immutability trigger', () => {
      expect(() => {
        db.prepare(`
          INSERT INTO case_notes (id, case_id, author, content, content_hash, version)
          VALUES (?, ?, 'Duplicate Insert', 'Collision test', ?, 1)
        `).run(noteId, testCaseId, 'b'.repeat(64));
      }).toThrowError(/NOTE_IMMUTABILITY_VIOLATION/);
    });

    it('SCEN-1.7: Mutation via analyst_notes compatibility view is blocked', () => {
      expect(() => {
        db.prepare('UPDATE analyst_notes SET content = ? WHERE id = ?').run('View Tamper', noteId);
      }).toThrowError(/cannot modify analyst_notes|NOTE_IMMUTABILITY_VIOLATION/);

      expect(() => {
        db.prepare('DELETE FROM analyst_notes WHERE id = ?').run(noteId);
      }).toThrowError(/cannot modify analyst_notes|NOTE_IMMUTABILITY_VIOLATION/);
    });
  });

  // =========================================================================
  // SCENARIO 2: Case Deletion & Evidence Cascade Protection
  // =========================================================================
  describe('Scenario 2: Case Deletion & Evidence Cascade Attacks', () => {
    let cascadeCaseId: string;
    let directEvidenceId: string;
    let junctionEvidenceId: string;
    let attachedNoteId: string;

    beforeEach(() => {
      cascadeCaseId = 'case-cascade-test-001';
      directEvidenceId = 'ev-direct-cascade-001';
      junctionEvidenceId = 'ev-junction-cascade-001';
      attachedNoteId = 'note-cascade-001';

      // 1. Create a dedicated case
      db.prepare(`
        INSERT INTO cases (id, title, status, priority, lead_analyst)
        VALUES (?, 'Cascade Vulnerability Probe Case', 'OPEN', 'HIGH', 'Analyst Cascade')
      `).run(cascadeCaseId);

      // 2. Attach evidence directly via evidence_ledger.case_id
      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score, immutable_lock
        ) VALUES (
          ?, ?, 'https://cisa.gov/advisory/aa26-001', 'CISA_ADVISORY', 'Direct Linked Evidence',
          ?, '{"cve": "CVE-2026-9999"}', 'Observed', 0.95, 1
        )
      `).run(directEvidenceId, cascadeCaseId, '1'.repeat(64));

      // 3. Create independent evidence and link via case_evidence junction
      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score, immutable_lock
        ) VALUES (
          ?, NULL, 'https://earthquake.usgs.gov/probe', 'USGS_EARTHQUAKE', 'Junction Linked Evidence',
          ?, '{"mag": 6.8}', 'Observed', 0.88, 1
        )
      `).run(junctionEvidenceId, '2'.repeat(64));

      db.prepare(`
        INSERT INTO case_evidence (id, case_id, evidence_id, attached_by)
        VALUES ('ce-cascade-001', ?, ?, 'Analyst Cascade')
      `).run(cascadeCaseId, junctionEvidenceId);

      // 4. Attach note
      db.prepare(`
        INSERT INTO case_notes (id, case_id, author, content, content_hash)
        VALUES (?, ?, 'Analyst Cascade', 'Note attached to cascade case', ?)
      `).run(attachedNoteId, cascadeCaseId, '3'.repeat(64));
    });

    it('SCEN-2.1: Direct SQL hard deletion `DELETE FROM cases` is blocked by immutability triggers without database corruption', () => {
      // Deleting a case with direct evidence triggers ON DELETE SET NULL on evidence_ledger,
      // which attempts an UPDATE on evidence_ledger, tripping trg_prevent_evidence_update.
      // Or it attempts cascade on case_notes, tripping trg_prevent_case_notes_delete.
      expect(() => {
        db.prepare('DELETE FROM cases WHERE id = ?').run(cascadeCaseId);
      }).toThrowError(/FOREIGN KEY constraint failed|IMMUTABILITY_VIOLATION/);

      // Verify that the case, notes, and evidence are completely uncorrupted
      const caseAfter = db.prepare('SELECT id, status FROM cases WHERE id = ?').get(cascadeCaseId) as any;
      expect(caseAfter).toBeDefined();

      const directEv = db.prepare('SELECT id, case_id FROM evidence_ledger WHERE id = ?').get(directEvidenceId) as any;
      expect(directEv.case_id).toBe(cascadeCaseId);

      const juncEv = db.prepare('SELECT id FROM evidence_ledger WHERE id = ?').get(junctionEvidenceId) as any;
      expect(juncEv).toBeDefined();

      const note = db.prepare('SELECT id FROM case_notes WHERE id = ?').get(attachedNoteId) as any;
      expect(note).toBeDefined();
    });

    it('SCEN-2.2: API DELETE /cases/:id safely soft-deletes (status=ARCHIVED) without mutating evidence or failing triggers', async () => {
      const res = await request(app)
        .delete(`/api/v1/cases/${cascadeCaseId}`)
        .set('x-bypass-csrf', 'true');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.status).toBe('ARCHIVED');
      expect(res.body.soft_deleted).toBe(true);

      // Verify case status in DB
      const caseRow = db.prepare('SELECT status, closed_at FROM cases WHERE id = ?').get(cascadeCaseId) as any;
      expect(caseRow.status).toBe('ARCHIVED');
      expect(caseRow.closed_at).not.toBeNull();

      // Verify evidence_ledger remains 100% intact and linked
      const directEv = db.prepare('SELECT id, case_id, content_fingerprint FROM evidence_ledger WHERE id = ?').get(directEvidenceId) as any;
      expect(directEv.case_id).toBe(cascadeCaseId);
      expect(directEv.content_fingerprint).toBe('1'.repeat(64));

      // Verify case_evidence junction row remains intact
      const juncRow = db.prepare('SELECT id FROM case_evidence WHERE case_id = ? AND evidence_id = ?').get(cascadeCaseId, junctionEvidenceId);
      expect(juncRow).toBeDefined();

      // Verify case_notes row remains intact
      const noteRow = db.prepare('SELECT id, content FROM case_notes WHERE id = ?').get(attachedNoteId) as any;
      expect(noteRow.content).toBe('Note attached to cascade case');
    });

    it('SCEN-2.3: Archived case still serves its full dossier and evidence list via API', async () => {
      // Archive case first
      await request(app).delete(`/api/v1/cases/${cascadeCaseId}`).set('x-bypass-csrf', 'true');

      // Dossier query
      const caseRes = await request(app).get(`/api/v1/cases/${cascadeCaseId}`);
      expect(caseRes.status).toBe(200);
      expect(caseRes.body.data.status).toBe('ARCHIVED');

      // Evidence list query (must retrieve both direct and junction attached evidence)
      const evRes = await request(app).get(`/api/v1/cases/${cascadeCaseId}/evidence`);
      expect(evRes.status).toBe(200);
      expect(evRes.body.items.length).toBe(2);

      const returnedIds = evRes.body.items.map((i: any) => i.id);
      expect(returnedIds).toContain(directEvidenceId);
      expect(returnedIds).toContain(junctionEvidenceId);
    });
  });

  // =========================================================================
  // SCENARIO 3: Analyst Notes Boundary & Injection Attacks
  // =========================================================================
  describe('Scenario 3: Analyst Notes Boundary & Injection Attacks', () => {
    it('SCEN-3.1: Rejects note with 0 characters (empty string)', async () => {
      const res = await request(app)
        .post(`/api/v1/cases/${testCaseId}/notes`)
        .set('x-bypass-csrf', 'true')
        .send({ author: 'Analyst', content: '' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('SCEN-3.2: Rejects note with only whitespace characters', async () => {
      const res = await request(app)
        .post(`/api/v1/cases/${testCaseId}/notes`)
        .set('x-bypass-csrf', 'true')
        .send({ author: 'Analyst', content: '   \n\t   ' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('SCEN-3.3: Accepts note with exactly 5,000 characters', async () => {
      const content5000 = 'X'.repeat(5000);
      const res = await request(app)
        .post(`/api/v1/cases/${testCaseId}/notes`)
        .set('x-bypass-csrf', 'true')
        .send({ author: 'Analyst', content: content5000 });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.content.length).toBe(5000);
      expect(res.body.data.version).toBe(1);
    });

    it('SCEN-3.4: Rejects note with exactly 5,001 characters', async () => {
      const content5001 = 'Y'.repeat(5001);
      const res = await request(app)
        .post(`/api/v1/cases/${testCaseId}/notes`)
        .set('x-bypass-csrf', 'true')
        .send({ author: 'Analyst', content: content5001 });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('SCEN-3.5: Preserves raw XSS payload integrity at API while renderSafeMarkdown neutralizes execution', async () => {
      const xssPayloads = [
        '<script>alert(1)</script>',
        '<img src="x" onerror="alert(document.cookie)">',
        '"><svg/onload=alert(1)>',
        '<iframe src="https://evil.com"></iframe>',
        'javascript:alert(1)'
      ];

      for (const payload of xssPayloads) {
        // Post to API: raw content must be preserved verbatim for evidentiary authenticity
        const res = await request(app)
          .post(`/api/v1/cases/${testCaseId}/notes`)
          .set('x-bypass-csrf', 'true')
          .send({ author: 'Security Analyst', content: payload });

        expect(res.status).toBe(201);
        expect(res.body.data.content).toBe(payload);

        // Verify frontend markdown renderer escapes all dangerous tags into harmless text entities
        const rendered = renderSafeMarkdown(payload);
        expect(rendered).not.toContain('<script');
        expect(rendered).not.toContain('<img');
        expect(rendered).not.toContain('<svg');
        expect(rendered).not.toContain('<iframe');

        // Confirm proper HTML entity escaping occurred
        if (payload.includes('<')) {
          expect(rendered).toContain('&lt;');
        }
        if (payload.includes('>')) {
          expect(rendered).toContain('&gt;');
        }
      }
    });

    it('SCEN-3.6: Neutralizes markdown image and link injection attacks in renderSafeMarkdown', () => {
      // 1. Markdown image syntax should NOT create an img tag
      const mdImg = '![exfil](https://attacker.com/leak.png)';
      const renderedImg = renderSafeMarkdown(mdImg);
      expect(renderedImg).not.toContain('<img');

      // 2. Markdown link with javascript pseudo-protocol should NOT generate a javascript link
      const mdJsLink = '[click me](javascript:alert(document.domain))';
      const renderedJsLink = renderSafeMarkdown(mdJsLink);
      expect(renderedJsLink).not.toContain('href="javascript:');

      // 3. Legitimate https link is safely converted with noopener
      const legitimateLink = '[CISA Advisory](https://cisa.gov/advisory-123)';
      const renderedLegit = renderSafeMarkdown(legitimateLink);
      expect(renderedLegit).toContain('href="https://cisa.gov/advisory-123"');
      expect(renderedLegit).toContain('rel="noopener noreferrer"');
    });

    it('SCEN-3.7: Correctly handles high-plane unicode, international alphabets, and emojis', async () => {
      const unicodeContent = '🚨 Urgent: Entity ☸️ "धर्म का पहिया" detected in Moscow (Москва) and Tokyo (東京)! 🛡️';

      const res = await request(app)
        .post(`/api/v1/cases/${testCaseId}/notes`)
        .set('x-bypass-csrf', 'true')
        .send({ author: 'Global Analyst', content: unicodeContent });

      expect(res.status).toBe(201);
      expect(res.body.data.content).toBe(unicodeContent);

      const rendered = renderSafeMarkdown(unicodeContent);
      expect(rendered).toContain('🚨');
      expect(rendered).toContain('धर्म का पहिया');
      expect(rendered).toContain('Москва');
      expect(rendered).toContain('東京');
    });

    it('SCEN-3.8: Handles notes containing null bytes or control characters cleanly', async () => {
      const nullByteContent = 'Evidence snippet: packet header \x00\x01\x02 binary stream';

      const res = await request(app)
        .post(`/api/v1/cases/${testCaseId}/notes`)
        .set('x-bypass-csrf', 'true')
        .send({ author: 'Analyst', content: nullByteContent });

      // Must succeed or fail cleanly with structured response, never crash
      expect([201, 400]).toContain(res.status);
      if (res.status === 201) {
        expect(res.body.data.content).toBe(nullByteContent);
      }
    });
  });

  // =========================================================================
  // SCENARIO 4: Concurrent & Duplicate Evidence Attachment
  // =========================================================================
  describe('Scenario 4: Concurrent & Duplicate Evidence Attachment', () => {
    it('SCEN-4.1: Attaching same evidence multiple times succeeds idempotently without SQL crash', async () => {
      // First attachment
      const res1 = await request(app)
        .post(`/api/v1/cases/${testCaseId}/evidence/attach`)
        .set('x-bypass-csrf', 'true')
        .send({ evidence_id: testEvidenceId, notes: 'First attachment' });

      expect(res1.status).toBe(200);
      expect(res1.body.success).toBe(true);
      expect(res1.body.attached).toBe(true);

      // Duplicate attachment of same evidence to same case
      const res2 = await request(app)
        .post(`/api/v1/cases/${testCaseId}/evidence/attach`)
        .set('x-bypass-csrf', 'true')
        .send({ evidence_id: testEvidenceId, notes: 'Duplicate attachment attempt' });

      expect(res2.status).toBe(200);
      expect(res2.body.success).toBe(true);
      expect(res2.body.attached).toBe(true);

      // Verify database junction has at most 1 row for this (case_id, evidence_id)
      const junctionRows = db.prepare(`
        SELECT count(*) as cnt FROM case_evidence WHERE case_id = ? AND evidence_id = ?
      `).get(testCaseId, testEvidenceId) as { cnt: number };

      expect(junctionRows.cnt).toBe(1);
    });

    it('SCEN-4.2: Concurrent parallel attachment requests resolve idempotently without deadlock or duplicate rows', async () => {
      const concurrentRequests = 15;
      const promises = Array.from({ length: concurrentRequests }).map((_, idx) =>
        request(app)
          .post(`/api/v1/cases/${testCaseId}/evidence/attach`)
          .set('x-bypass-csrf', 'true')
          .send({ evidence_id: testEvidenceId, notes: `Concurrent attempt #${idx}` })
      );

      const results = await Promise.all(promises);

      for (const res of results) {
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      }

      const count = db.prepare(`
        SELECT count(*) as cnt FROM case_evidence WHERE case_id = ? AND evidence_id = ?
      `).get(testCaseId, testEvidenceId) as { cnt: number };

      expect(count.cnt).toBe(1);
    });

    it('SCEN-4.3: Evidence list endpoint returns deduplicated records when evidence is linked both directly and via junction', async () => {
      // Create a new distinct evidence item
      const dualEvId = 'ev-dual-link-001';
      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score, immutable_lock
        ) VALUES (
          ?, ?, 'https://cert.europa.eu/dual', 'RSS_FEED', 'Dual Linked Evidence',
          ?, '{"headline": "dual link"}', 'Observed', 0.9, 1
        )
      `).run(dualEvId, testCaseId, '9'.repeat(64));

      // Also attach it via case_evidence junction
      await request(app)
        .post(`/api/v1/cases/${testCaseId}/evidence/attach`)
        .set('x-bypass-csrf', 'true')
        .send({ evidence_id: dualEvId });

      // Query GET /cases/:id/evidence
      const res = await request(app).get(`/api/v1/cases/${testCaseId}/evidence`);
      expect(res.status).toBe(200);

      // Filter by dualEvId
      const matches = res.body.items.filter((item: any) => item.id === dualEvId);
      expect(matches.length).toBe(1);
    });

    it('SCEN-4.4: Attaching non-existent evidence returns 404 cleanly', async () => {
      const res = await request(app)
        .post(`/api/v1/cases/${testCaseId}/evidence/attach`)
        .set('x-bypass-csrf', 'true')
        .send({ evidence_id: 'ev-nonexistent-9999' });

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });

    it('SCEN-4.5: Attaching evidence to non-existent case returns 404 or clean error', async () => {
      const res = await request(app)
        .post('/api/v1/cases/case-nonexistent-9999/evidence/attach')
        .set('x-bypass-csrf', 'true')
        .send({ evidence_id: testEvidenceId });

      // Note: If case does not exist, foreign key constraint on case_evidence fails if FKs are checked
      // Let's observe the actual response code and behavior
      expect([400, 404, 409, 500]).toContain(res.status);
    });
  });
});
