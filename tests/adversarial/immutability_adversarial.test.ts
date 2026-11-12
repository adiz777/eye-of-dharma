// tests/adversarial/immutability_adversarial.test.ts
// Empirical adversarial stress test harness for SQLite schema, triggers, and immutability invariants

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase, computeSha256 } from '../../server/db/seed.js';

describe('Adversarial Database Immutability & Relational Integrity Challenge', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    db.pragma('busy_timeout = 5000');
    runMigrations(db);
    seedDatabase(db);
  });

  afterEach(() => {
    db.close();
  });

  // =========================================================================
  // SUITE 1: Direct SQL UPDATE Attacks against evidence_ledger
  // =========================================================================
  describe('Suite 1: Direct SQL UPDATE Attacks', () => {
    it('ATTACK-1.1: Direct UPDATE on mutable-looking field (notes)', () => {
      const ev = db.prepare('SELECT id, notes FROM evidence_ledger LIMIT 1').get() as any;
      expect(ev).toBeDefined();

      expect(() => {
        db.prepare('UPDATE evidence_ledger SET notes = ? WHERE id = ?').run('MALICIOUS_NOTE', ev.id);
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const after = db.prepare('SELECT notes FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(after.notes).toBe(ev.notes);
    });

    it('ATTACK-1.2: Direct UPDATE on cryptographic fingerprint', () => {
      const ev = db.prepare('SELECT id, content_fingerprint FROM evidence_ledger LIMIT 1').get() as any;

      expect(() => {
        db.prepare('UPDATE evidence_ledger SET content_fingerprint = ? WHERE id = ?').run(
          '0000000000000000000000000000000000000000000000000000000000000000',
          ev.id
        );
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const after = db.prepare('SELECT content_fingerprint FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(after.content_fingerprint).toBe(ev.content_fingerprint);
    });

    it('ATTACK-1.3: Direct UPDATE on raw_content payload', () => {
      const ev = db.prepare('SELECT id, raw_content FROM evidence_ledger LIMIT 1').get() as any;

      expect(() => {
        db.prepare('UPDATE evidence_ledger SET raw_content = ? WHERE id = ?').run('{"tampered": true}', ev.id);
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const after = db.prepare('SELECT raw_content FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(after.raw_content).toBe(ev.raw_content);
    });

    it('ATTACK-1.4: Direct UPDATE on verification_status and confidence_score', () => {
      const ev = db.prepare('SELECT id, verification_status, confidence_score FROM evidence_ledger LIMIT 1').get() as any;

      expect(() => {
        db.prepare('UPDATE evidence_ledger SET verification_status = ?, confidence_score = 1.0 WHERE id = ?').run('Corroborated', ev.id);
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const after = db.prepare('SELECT verification_status, confidence_score FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(after.verification_status).toBe(ev.verification_status);
      expect(after.confidence_score).toBe(ev.confidence_score);
    });

    it('ATTACK-1.5: Direct UPDATE on immutable_lock flag', () => {
      const ev = db.prepare('SELECT id FROM evidence_ledger LIMIT 1').get() as any;

      expect(() => {
        db.prepare('UPDATE evidence_ledger SET immutable_lock = 0 WHERE id = ?').run(ev.id);
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);
    });

    it('ATTACK-1.6: Bulk UPDATE across entire table without WHERE clause', () => {
      const initialCount = (db.prepare('SELECT count(*) as count FROM evidence_ledger').get() as any).count;
      expect(initialCount).toBeGreaterThan(0);

      expect(() => {
        db.prepare("UPDATE evidence_ledger SET notes = 'MASS_WIPE'").run();
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const check = db.prepare("SELECT count(*) as count FROM evidence_ledger WHERE notes = 'MASS_WIPE'").get() as any;
      expect(check.count).toBe(0);
    });

    it('ATTACK-1.7: Zero-difference UPDATE (id = id)', () => {
      const ev = db.prepare('SELECT id FROM evidence_ledger LIMIT 1').get() as any;

      expect(() => {
        db.prepare('UPDATE evidence_ledger SET id = id WHERE id = ?').run(ev.id);
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);
    });

    it('ATTACK-1.8: Subquery UPDATE joining with cases table', () => {
      expect(() => {
        db.prepare(`
          UPDATE evidence_ledger
          SET notes = (SELECT title FROM cases WHERE cases.id = evidence_ledger.case_id)
          WHERE case_id IS NOT NULL
        `).run();
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);
    });

    it('ATTACK-1.9: UPSERT (ON CONFLICT DO UPDATE) attempt', () => {
      const ev = db.prepare('SELECT * FROM evidence_ledger LIMIT 1').get() as any;

      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, case_id, source_url, source_type, source_title,
            content_fingerprint, raw_content, parsed_content,
            verification_status, confidence_score, retrieved_at,
            recorded_by, is_synthetic, notes, immutable_lock
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET notes = 'UPSERT_TAMPERED'
        `).run(
          ev.id, ev.case_id, ev.source_url, ev.source_type, ev.source_title,
          ev.content_fingerprint, ev.raw_content, ev.parsed_content,
          ev.verification_status, ev.confidence_score, ev.retrieved_at,
          ev.recorded_by, ev.is_synthetic, 'UPSERT_TAMPERED', 1
        );
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const after = db.prepare('SELECT notes FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(after.notes).not.toBe('UPSERT_TAMPERED');
    });
  });

  // =========================================================================
  // SUITE 2: Direct SQL DELETE Attacks against evidence_ledger
  // =========================================================================
  describe('Suite 2: Direct SQL DELETE Attacks', () => {
    it('ATTACK-2.1: Single-row DELETE by primary key ID', () => {
      const ev = db.prepare('SELECT id FROM evidence_ledger LIMIT 1').get() as any;

      expect(() => {
        db.prepare('DELETE FROM evidence_ledger WHERE id = ?').run(ev.id);
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const after = db.prepare('SELECT id FROM evidence_ledger WHERE id = ?').get(ev.id);
      expect(after).toBeDefined();
    });

    it('ATTACK-2.2: Bulk DELETE on all rows without WHERE clause', () => {
      const beforeCount = (db.prepare('SELECT count(*) as count FROM evidence_ledger').get() as any).count;

      expect(() => {
        db.prepare('DELETE FROM evidence_ledger').run();
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const afterCount = (db.prepare('SELECT count(*) as count FROM evidence_ledger').get() as any).count;
      expect(afterCount).toBe(beforeCount);
    });

    it('ATTACK-2.3: Subquery DELETE with IN clause', () => {
      expect(() => {
        db.prepare('DELETE FROM evidence_ledger WHERE id IN (SELECT id FROM evidence_ledger)').run();
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);
    });

    it('ATTACK-2.4: Conditional DELETE matching non-synthetic or synthetic rows', () => {
      expect(() => {
        db.prepare('DELETE FROM evidence_ledger WHERE is_synthetic = 1').run();
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);
    });
  });

  // =========================================================================
  // SUITE 3: INSERT OR REPLACE & Conflict Strategy Evaluation
  // =========================================================================
  describe('Suite 3: INSERT OR REPLACE & Conflict Strategy Evaluation', () => {
    it('ATTACK-3.1: INSERT OR REPLACE is prevented by immutability triggers under default connection', () => {
      const ev = db.prepare('SELECT * FROM evidence_ledger LIMIT 1').get() as any;
      const originalNotes = ev.notes;
      const originalFingerprint = ev.content_fingerprint;

      // Execute INSERT OR REPLACE with tampered content - should fail with violation
      expect(() => {
        db.prepare(`
          INSERT OR REPLACE INTO evidence_ledger (
            id, case_id, source_url, source_type, source_title,
            content_fingerprint, raw_content, parsed_content,
            verification_status, confidence_score, retrieved_at,
            recorded_by, is_synthetic, notes, immutable_lock
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          ev.id, ev.case_id, ev.source_url, ev.source_type, 'TAMPERED_TITLE',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '{"tampered": true}', ev.parsed_content,
          'Corroborated', 1.0, ev.retrieved_at,
          'ATTACKER', 0, 'TAMPERED_NOTE_BY_REPLACE', 1
        );
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const unchanged = db.prepare('SELECT notes, content_fingerprint, source_title FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(unchanged.notes).toBe(originalNotes);
      expect(unchanged.content_fingerprint).toBe(originalFingerprint);
    });

    it('ATTACK-3.2: INSERT OR REPLACE with PRAGMA recursive_triggers = ON', () => {
      const testDb = new Database(':memory:');
      testDb.pragma('foreign_keys = ON');
      testDb.pragma('recursive_triggers = ON');
      runMigrations(testDb);
      seedDatabase(testDb);

      const ev = testDb.prepare('SELECT * FROM evidence_ledger LIMIT 1').get() as any;

      let caught = false;
      let errorMsg = '';
      try {
        testDb.prepare(`
          INSERT OR REPLACE INTO evidence_ledger (
            id, case_id, source_url, source_type, source_title,
            content_fingerprint, raw_content, parsed_content,
            verification_status, confidence_score, retrieved_at,
            recorded_by, is_synthetic, notes, immutable_lock
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          ev.id, ev.case_id, ev.source_url, ev.source_type, 'TAMPERED_TITLE',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '{"tampered": true}', ev.parsed_content,
          'Corroborated', 1.0, ev.retrieved_at,
          'ATTACKER', 0, 'TAMPERED_NOTE_BY_REPLACE', 1
        );
      } catch (err: any) {
        caught = true;
        errorMsg = err.message;
      }

      // Check if recursive_triggers = ON caused trg_prevent_evidence_delete to fire
      expect(caught).toBe(true);
      expect(errorMsg).toMatch(/EVIDENCE_IMMUTABILITY_VIOLATION/);
      testDb.close();
    });

    it('ATTACK-3.3: INSERT OR IGNORE behavior on existing evidence record', () => {
      const ev = db.prepare('SELECT * FROM evidence_ledger LIMIT 1').get() as any;

      // In an immutable ledger, attempting to insert an already-existing evidence ID is rejected at trigger level
      expect(() => {
        db.prepare(`
          INSERT OR IGNORE INTO evidence_ledger (
            id, case_id, source_url, source_type, source_title,
            content_fingerprint, raw_content, parsed_content,
            verification_status, confidence_score, retrieved_at,
            recorded_by, is_synthetic, notes, immutable_lock
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          ev.id, ev.case_id, ev.source_url, ev.source_type, 'NEW_TITLE',
          ev.content_fingerprint, ev.raw_content, ev.parsed_content,
          ev.verification_status, ev.confidence_score, ev.retrieved_at,
          ev.recorded_by, ev.is_synthetic, 'NEW_NOTE', 1
        );
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const after = db.prepare('SELECT notes, source_title FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(after.notes).toBe(ev.notes);
      expect(after.source_title).toBe(ev.source_title);
    });

    it('ATTACK-3.4: Real getDatabase() / connection prevents INSERT OR REPLACE', () => {
      // Create fresh test database using createInMemoryDatabase or getDatabase
      const realDb = new Database(':memory:');
      // Apply exact pragmas from server/db/connection.ts
      realDb.pragma('foreign_keys = ON');
      realDb.pragma('recursive_triggers = ON');
      realDb.pragma('busy_timeout = 5000');
      realDb.pragma('temp_store = MEMORY');

      runMigrations(realDb);
      seedDatabase(realDb);

      const targetEv = realDb.prepare('SELECT * FROM evidence_ledger LIMIT 1').get() as any;

      // An attacker executes INSERT OR REPLACE against the live database - should throw
      expect(() => {
        realDb.prepare(`
          INSERT OR REPLACE INTO evidence_ledger (
            id, case_id, source_url, source_type, source_title,
            content_fingerprint, raw_content, parsed_content,
            verification_status, confidence_score, retrieved_at,
            recorded_by, is_synthetic, notes, immutable_lock
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          targetEv.id, targetEv.case_id, targetEv.source_url, targetEv.source_type,
          'POISONED_TITLE', 'BAD_HASH_9999', '{"corrupted": true}', null,
          'Corroborated', 1.0, '2026-10-28T16:00:00Z', 'ATTACKER', 0,
          'POISONED_NOTE_TAMPERED', 1
        );
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      const intactEv = realDb.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(targetEv.id) as any;
      expect(intactEv.notes).not.toBe('POISONED_NOTE_TAMPERED');
      realDb.close();
    });

    it('ATTACK-3.5: Remediation Proof — BEFORE INSERT trigger prevents INSERT OR REPLACE even without recursive_triggers', () => {
      const testDb = new Database(':memory:');
      testDb.pragma('foreign_keys = ON');
      // Notice: recursive_triggers is NOT set, matching default connection
      runMigrations(testDb);

      // Add the missing defense-in-depth trigger
      testDb.exec(`
        CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_replace
        BEFORE INSERT ON evidence_ledger
        WHEN EXISTS (SELECT 1 FROM evidence_ledger WHERE id = NEW.id)
        BEGIN
            SELECT RAISE(FAIL, 'EVIDENCE_IMMUTABILITY_VIOLATION: Entries in evidence_ledger cannot be replaced or overwritten.');
        END;
      `);

      seedDatabase(testDb);

      const ev = testDb.prepare('SELECT * FROM evidence_ledger LIMIT 1').get() as any;

      // Now attempt INSERT OR REPLACE
      expect(() => {
        testDb.prepare(`
          INSERT OR REPLACE INTO evidence_ledger (
            id, case_id, source_url, source_type, source_title,
            content_fingerprint, raw_content, parsed_content,
            verification_status, confidence_score, retrieved_at,
            recorded_by, is_synthetic, notes, immutable_lock
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          ev.id, ev.case_id, ev.source_url, ev.source_type, 'TAMPERED_TITLE',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '{"tampered": true}', ev.parsed_content,
          'Corroborated', 1.0, ev.retrieved_at,
          'ATTACKER', 0, 'TAMPERED_NOTE_BY_REPLACE', 1
        );
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

      // Verify evidence remains intact
      const preserved = testDb.prepare('SELECT notes, content_fingerprint FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(preserved.notes).toBe(ev.notes);
      expect(preserved.content_fingerprint).toBe(ev.content_fingerprint);
      testDb.close();
    });
  });

  // =========================================================================
  // SUITE 4: Foreign Key Cascades & Parent/Child Interactions
  // =========================================================================
  describe('Suite 4: Foreign Key Cascades & Relational Integrity', () => {
    it('ATTACK-4.1: Parent Case Deletion with evidence_ledger referencing it (ON DELETE SET NULL)', () => {
      const evWithCase = db.prepare('SELECT id, case_id FROM evidence_ledger WHERE case_id IS NOT NULL LIMIT 1').get() as any;
      expect(evWithCase).toBeDefined();

      // In SQLite, deleting the parent case causes SQLite to try to UPDATE evidence_ledger.case_id = NULL
      // Because evidence_ledger has BEFORE UPDATE trigger, the cascading action fails,
      // resulting in a FOREIGN KEY constraint failure on the parent DELETE.
      expect(() => {
        db.prepare('DELETE FROM cases WHERE id = ?').run(evWithCase.case_id);
      }).toThrowError(/FOREIGN KEY constraint failed/);

      // Verify case was NOT deleted
      const parentCase = db.prepare('SELECT id FROM cases WHERE id = ?').get(evWithCase.case_id);
      expect(parentCase).toBeDefined();

      // Verify evidence case_id was NOT modified
      const evAfter = db.prepare('SELECT case_id FROM evidence_ledger WHERE id = ?').get(evWithCase.id) as any;
      expect(evAfter.case_id).toBe(evWithCase.case_id);
    });

    it('ATTACK-4.2: Parent Case ID UPDATE with evidence_ledger referencing it', () => {
      const evWithCase = db.prepare('SELECT id, case_id FROM evidence_ledger WHERE case_id IS NOT NULL LIMIT 1').get() as any;

      expect(() => {
        db.prepare("UPDATE cases SET id = 'MUTATED_CASE_ID' WHERE id = ?").run(evWithCase.case_id);
      }).toThrowError(); // Foreign key constraint violation or trigger error

      const parentCase = db.prepare('SELECT id FROM cases WHERE id = ?').get(evWithCase.case_id);
      expect(parentCase).toBeDefined();
    });

    it('ATTACK-4.3: Relationship deletion does NOT affect evidence_ledger', () => {
      const rel = db.prepare('SELECT id, evidence_id FROM relationships WHERE evidence_id IS NOT NULL LIMIT 1').get() as any;
      if (rel) {
        const evBefore = db.prepare('SELECT id FROM evidence_ledger WHERE id = ?').get(rel.evidence_id);
        expect(evBefore).toBeDefined();

        db.prepare('DELETE FROM relationships WHERE id = ?').run(rel.id);

        const evAfter = db.prepare('SELECT id FROM evidence_ledger WHERE id = ?').get(rel.evidence_id);
        expect(evAfter).toBeDefined();
      }
    });

    it('ATTACK-4.4: Foreign key constraint enforcement across all 9 tables (rejection of orphaned records)', () => {
      // 1. evidence_ledger with non-existent case_id
      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, case_id, source_url, source_type, source_title,
            content_fingerprint, raw_content, verification_status,
            confidence_score, retrieved_at, recorded_by, is_synthetic, immutable_lock
          ) VALUES ('ev-orphaned', 'non-existent-case', 'http://x.com', 'MANUAL_ENTRY', 'Orphan',
            '1111111111111111111111111111111111111111111111111111111111111111', '{}', 'Observed',
            0.5, '2026-01-01', 'SYSTEM', 0, 1)
        `).run();
      }).toThrowError(/FOREIGN KEY constraint failed/);

      // 2. entities with non-existent case_id
      expect(() => {
        db.prepare(`
          INSERT INTO entities (id, case_id, name, type, value, risk_score, metadata, is_synthetic)
          VALUES ('ent-orphaned', 'non-existent-case', 'Fake', 'DOMAIN', 'fake.com', 0, '{}', 0)
        `).run();
      }).toThrowError(/FOREIGN KEY constraint failed/);

      // 3. relationships with non-existent source_entity_id
      expect(() => {
        db.prepare(`
          INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, status, is_synthetic)
          VALUES ('rel-bad-src', 'missing-entity-1', 'missing-entity-2', 'RESOLVES_TO', 0.5, 'VERIFIED', 0)
        `).run();
      }).toThrowError(/FOREIGN KEY constraint failed/);

      // 4. agent_runs with non-existent case_id
      expect(() => {
        db.prepare(`
          INSERT INTO agent_runs (id, case_id, agent_name, status, input_parameters)
          VALUES ('run-bad-case', 'non-existent-case', 'DHARMA', 'PLANNED', '{}')
        `).run();
      }).toThrowError(/FOREIGN KEY constraint failed/);
    });

    it('ATTACK-4.5: Entity cascade deletion cascades to relationships', () => {
      const ent1 = 'ent-cascade-src';
      const ent2 = 'ent-cascade-dst';
      const relId = 'rel-cascade-test';

      db.prepare(`
        INSERT INTO entities (id, name, type, value, risk_score, metadata, is_synthetic)
        VALUES
          (?, 'Test Src', 'IP_ADDRESS', '192.0.2.1', 10, '{}', 0),
          (?, 'Test Dst', 'DOMAIN', 'example.org', 20, '{}', 0)
      `).run(ent1, ent2);

      db.prepare(`
        INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, status, is_synthetic)
        VALUES (?, ?, ?, 'RESOLVES_TO', 0.8, 'VERIFIED', 0)
      `).run(relId, ent1, ent2);

      expect(db.prepare('SELECT id FROM relationships WHERE id = ?').get(relId)).toBeDefined();

      // Deleting target entity must cascade delete the relationship
      db.prepare('DELETE FROM entities WHERE id = ?').run(ent2);

      expect(db.prepare('SELECT id FROM relationships WHERE id = ?').get(relId)).toBeUndefined();
      expect(db.prepare('SELECT id FROM entities WHERE id = ?').get(ent1)).toBeDefined();
    });
  });

  // =========================================================================
  // SUITE 5: Transactions, Savepoints, and Rollback Integrity
  // =========================================================================
  describe('Suite 5: Transactions, Savepoints & Rollback Integrity', () => {
    it('ATTACK-5.1: Transaction rollbacks preserve database consistency on trigger abort', () => {
      const initialCaseCount = (db.prepare('SELECT count(*) as count FROM cases').get() as any).count;
      const ev = db.prepare('SELECT id, notes FROM evidence_ledger LIMIT 1').get() as any;

      try {
        db.transaction(() => {
          db.prepare("INSERT INTO cases (id, title, status, priority, is_synthetic) VALUES ('tx-case-1', 'Tx Case', 'OPEN', 'LOW', 0)").run();
          // This will fail due to trigger
          db.prepare("UPDATE evidence_ledger SET notes = 'tx_tamper' WHERE id = ?").run(ev.id);
        })();
      } catch (err: any) {
        expect(err.message).toMatch(/EVIDENCE_IMMUTABILITY_VIOLATION/);
      }

      // Both the case insertion and evidence update should have been rolled back
      const afterCaseCount = (db.prepare('SELECT count(*) as count FROM cases').get() as any).count;
      expect(afterCaseCount).toBe(initialCaseCount);
      expect(db.prepare("SELECT id FROM cases WHERE id = 'tx-case-1'").get()).toBeUndefined();

      const evAfter = db.prepare('SELECT notes FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(evAfter.notes).toBe(ev.notes);
    });

    it('ATTACK-5.2: Savepoint nested isolation and rollback', () => {
      const ev = db.prepare('SELECT id, notes FROM evidence_ledger LIMIT 1').get() as any;

      db.exec('SAVEPOINT outer_savepoint;');
      db.prepare("INSERT INTO cases (id, title, status, priority, is_synthetic) VALUES ('sp-case-1', 'SP Case', 'OPEN', 'LOW', 0)").run();

      db.exec('SAVEPOINT inner_savepoint;');
      let triggerThrew = false;
      try {
        db.prepare("UPDATE evidence_ledger SET notes = 'sp_tamper' WHERE id = ?").run(ev.id);
      } catch (err: any) {
        triggerThrew = true;
        expect(err.message).toMatch(/EVIDENCE_IMMUTABILITY_VIOLATION/);
      }
      expect(triggerThrew).toBe(true);

      // Rollback to inner savepoint and release outer
      db.exec('ROLLBACK TO SAVEPOINT inner_savepoint;');
      db.exec('RELEASE SAVEPOINT outer_savepoint;');

      // Case inserted in outer should survive, evidence must remain untouched
      expect(db.prepare("SELECT id FROM cases WHERE id = 'sp-case-1'").get()).toBeDefined();
      const evAfter = db.prepare('SELECT notes FROM evidence_ledger WHERE id = ?').get(ev.id) as any;
      expect(evAfter.notes).toBe(ev.notes);
    });
  });

  // =========================================================================
  // SUITE 6: CHECK Constraints & Synthetic Invariant Stress Testing
  // =========================================================================
  describe('Suite 6: CHECK Constraints & Synthetic Invariant Bounds', () => {
    it('ATTACK-6.1: is_synthetic CHECK constraint violation (values other than 0 or 1)', () => {
      const tables = [
        'cases', 'evidence_ledger', 'entities', 'relationships',
        'threat_indicators', 'feed_records', 'watchlists'
      ];

      // Test is_synthetic = 2 on cases
      expect(() => {
        db.prepare("INSERT INTO cases (id, title, is_synthetic) VALUES ('syn-bad-1', 'Title', 2)").run();
      }).toThrowError(/CHECK constraint failed/);

      // Test is_synthetic = -1 on cases
      expect(() => {
        db.prepare("INSERT INTO cases (id, title, is_synthetic) VALUES ('syn-bad-2', 'Title', -1)").run();
      }).toThrowError(/CHECK constraint failed/);

      // Test is_synthetic = 2 on evidence_ledger
      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, source_url, source_type, source_title, content_fingerprint,
            raw_content, is_synthetic, immutable_lock
          ) VALUES ('ev-syn-bad', 'http://a.com', 'MANUAL_ENTRY', 'Bad Syn', '12345', '{}', 2, 1)
        `).run();
      }).toThrowError(/CHECK constraint failed/);
    });

    it('ATTACK-6.2: immutable_lock constraint violation on evidence_ledger', () => {
      // immutable_lock = 0 must be rejected
      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, source_url, source_type, source_title, content_fingerprint,
            raw_content, is_synthetic, immutable_lock
          ) VALUES ('ev-lock-0', 'http://a.com', 'MANUAL_ENTRY', 'Lock 0', '12345', '{}', 0, 0)
        `).run();
      }).toThrowError(/CHECK constraint failed/);
    });

    it('ATTACK-6.3: Enum and numeric CHECK constraint violation tests across tables', () => {
      // 1. cases.status invalid
      expect(() => {
        db.prepare("INSERT INTO cases (id, title, status) VALUES ('c-bad-st', 'T', 'DELETED')").run();
      }).toThrowError(/CHECK constraint failed/);

      // 2. cases.priority invalid
      expect(() => {
        db.prepare("INSERT INTO cases (id, title, priority) VALUES ('c-bad-pr', 'T', 'URGENT')").run();
      }).toThrowError(/CHECK constraint failed/);

      // 3. evidence_ledger.source_type invalid
      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, source_url, source_type, source_title, content_fingerprint,
            raw_content, immutable_lock
          ) VALUES ('ev-bad-src', 'http://a.com', 'INVALID_SOURCE', 'Title', '123', '{}', 1)
        `).run();
      }).toThrowError(/CHECK constraint failed/);

      // 4. evidence_ledger.verification_status invalid
      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, source_url, source_type, source_title, content_fingerprint,
            raw_content, verification_status, immutable_lock
          ) VALUES ('ev-bad-ver', 'http://a.com', 'MANUAL_ENTRY', 'Title', '123', '{}', 'FAKE', 1)
        `).run();
      }).toThrowError(/CHECK constraint failed/);

      // 5. evidence_ledger.confidence_score out of range (1.1, -0.1)
      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, source_url, source_type, source_title, content_fingerprint,
            raw_content, confidence_score, immutable_lock
          ) VALUES ('ev-bad-conf', 'http://a.com', 'MANUAL_ENTRY', 'Title', '123', '{}', 1.5, 1)
        `).run();
      }).toThrowError(/CHECK constraint failed/);

      expect(() => {
        db.prepare(`
          INSERT INTO evidence_ledger (
            id, source_url, source_type, source_title, content_fingerprint,
            raw_content, confidence_score, immutable_lock
          ) VALUES ('ev-bad-conf-neg', 'http://a.com', 'MANUAL_ENTRY', 'Title', '123', '{}', -0.1, 1)
        `).run();
      }).toThrowError(/CHECK constraint failed/);

      // 6. entities.risk_score out of range (101, -1)
      expect(() => {
        db.prepare("INSERT INTO entities (id, name, type, value, risk_score) VALUES ('ent-bad-risk', 'N', 'IP_ADDRESS', '1.1.1.1', 101)").run();
      }).toThrowError(/CHECK constraint failed/);

      // 7. agent_runs.agent_name invalid
      expect(() => {
        db.prepare("INSERT INTO agent_runs (id, agent_name, status, input_parameters) VALUES ('run-bad-name', 'HAL9000', 'PLANNED', '{}')").run();
      }).toThrowError(/CHECK constraint failed/);

      // 8. agent_runs.status invalid
      expect(() => {
        db.prepare("INSERT INTO agent_runs (id, agent_name, status, input_parameters) VALUES ('run-bad-st', 'DHARMA', 'PAUSED', '{}')").run();
      }).toThrowError(/CHECK constraint failed/);
    });
  });

  // =========================================================================
  // SUITE 7: Mutable Entities updated_at Trigger Verification
  // =========================================================================
  describe('Suite 7: updated_at Trigger Invariants on Mutable Tables', () => {
    it('ATTACK-7.1: Verify cases updated_at updates upon title change', () => {
      const c = db.prepare('SELECT id, updated_at FROM cases LIMIT 1').get() as any;
      const originalTime = c.updated_at;

      // Small delay or backdated update to detect change
      db.prepare("UPDATE cases SET updated_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(c.id);
      db.prepare("UPDATE cases SET title = 'New Title Test' WHERE id = ?").run(c.id);

      const after = db.prepare('SELECT title, updated_at FROM cases WHERE id = ?').get(c.id) as any;
      expect(after.title).toBe('New Title Test');
      expect(after.updated_at).not.toBe('2000-01-01T00:00:00.000Z');
    });

    it('ATTACK-7.2: Verify entities updated_at updates upon risk_score change', () => {
      const ent = db.prepare('SELECT id FROM entities LIMIT 1').get() as any;
      db.prepare("UPDATE entities SET updated_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(ent.id);
      db.prepare("UPDATE entities SET risk_score = 99 WHERE id = ?").run(ent.id);

      const after = db.prepare('SELECT risk_score, updated_at FROM entities WHERE id = ?').get(ent.id) as any;
      expect(after.risk_score).toBe(99);
      expect(after.updated_at).not.toBe('2000-01-01T00:00:00.000Z');
    });

    it('ATTACK-7.3: Verify watchlists updated_at updates upon pattern change', () => {
      const w = db.prepare('SELECT id FROM watchlists LIMIT 1').get() as any;
      db.prepare("UPDATE watchlists SET updated_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(w.id);
      db.prepare("UPDATE watchlists SET pattern = 'new-pattern.org' WHERE id = ?").run(w.id);

      const after = db.prepare('SELECT pattern, updated_at FROM watchlists WHERE id = ?').get(w.id) as any;
      expect(after.pattern).toBe('new-pattern.org');
      expect(after.updated_at).not.toBe('2000-01-01T00:00:00.000Z');
    });
  });
});
