// tests/integration/db.test.ts
// Integration tests for SQLite schema, migrations, immutability triggers, and deterministic seed data

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase, getSyntheticCounts, computeSha256 } from '../../server/db/seed.js';

describe('Database Schema & Migrations Integration', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    db.pragma('recursive_triggers = ON');
    db.pragma('busy_timeout = 5000');
  });

  afterEach(() => {
    db.close();
  });

  it('should migrate all 9 normalized tables and indexes successfully', () => {
    runMigrations(db);

    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all()
      .map((row: any) => row.name);

    const expectedTables = [
      'cases',
      'evidence_ledger',
      'entities',
      'relationships',
      'threat_indicators',
      'feed_records',
      'watchlists',
      'audit_events',
      'agent_runs'
    ];

    for (const tbl of expectedTables) {
      expect(tables).toContain(tbl);
    }
  });

  it('should enforce physical immutability triggers on evidence_ledger (prohibit UPDATE and DELETE)', () => {
    runMigrations(db);

    const rawPayload = JSON.stringify({ event: 'SCADA anomaly observed' });
    const fingerprint = computeSha256(rawPayload);

    // 1. Insert valid evidence record
    db.prepare(`
      INSERT INTO evidence_ledger (
        id, case_id, source_url, source_type, source_title,
        content_fingerprint, raw_content, parsed_content,
        verification_status, confidence_score, retrieved_at,
        recorded_by, is_synthetic, notes, immutable_lock
      ) VALUES (
        'ev-test-001', null, 'https://example.com/log', 'MANUAL_ENTRY', 'Test Log',
        ?, ?, null,
        'Observed', 0.9, '2026-01-01T00:00:00Z',
        'SYSTEM', 0, 'Original note', 1
      )
    `).run(fingerprint, rawPayload);

    // 2. Verify UPDATE is strictly prevented by database trigger
    expect(() => {
      db.prepare("UPDATE evidence_ledger SET notes = 'tampered note' WHERE id = 'ev-test-001'").run();
    }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

    expect(() => {
      db.prepare("UPDATE evidence_ledger SET raw_content = 'altered content' WHERE id = 'ev-test-001'").run();
    }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

    // 3. Verify DELETE is strictly prevented by database trigger
    expect(() => {
      db.prepare("DELETE FROM evidence_ledger WHERE id = 'ev-test-001'").run();
    }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

    // 4. Verify record remains intact and unaltered
    const record = db.prepare("SELECT * FROM evidence_ledger WHERE id = 'ev-test-001'").get() as any;
    expect(record).toBeDefined();
    expect(record.notes).toBe('Original note');
    expect(record.content_fingerprint).toBe(fingerprint);
  });

  it('should strictly prohibit INSERT OR REPLACE and UPSERT overwriting existing evidence records', () => {
    runMigrations(db);

    const rawPayload = JSON.stringify({ event: 'Immutable audit entry' });
    const fingerprint = computeSha256(rawPayload);

    db.prepare(`
      INSERT INTO evidence_ledger (
        id, source_url, source_type, source_title,
        content_fingerprint, raw_content, parsed_content,
        verification_status, confidence_score, retrieved_at,
        recorded_by, is_synthetic, notes, immutable_lock
      ) VALUES (
        'ev-locked-001', 'https://cisa.gov/advisory', 'MANUAL_ENTRY', 'CISA Advisory',
        ?, ?, '{}',
        'Corroborated', 1.0, '2026-01-01T00:00:00Z',
        'analyst-1', 0, 'Original locked note', 1
      )
    `).run(fingerprint, rawPayload);

    // Attempt INSERT OR REPLACE
    expect(() => {
      db.prepare(`
        INSERT OR REPLACE INTO evidence_ledger (
          id, source_url, source_type, source_title,
          content_fingerprint, raw_content, parsed_content,
          verification_status, confidence_score, retrieved_at,
          recorded_by, is_synthetic, notes, immutable_lock
        ) VALUES (
          'ev-locked-001', 'https://tampered.com', 'MANUAL_ENTRY', 'Tampered Advisory',
          'spoofed_sha', '{}', '{}',
          'Unverified', 0.1, '2026-02-01T00:00:00Z',
          'adversary', 0, 'Tampered note', 1
        )
      `).run();
    }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

    // Attempt UPSERT (ON CONFLICT DO UPDATE)
    expect(() => {
      db.prepare(`
        INSERT INTO evidence_ledger (
          id, source_url, source_type, source_title,
          content_fingerprint, raw_content, parsed_content,
          verification_status, confidence_score, retrieved_at,
          recorded_by, is_synthetic, notes, immutable_lock
        ) VALUES (
          'ev-locked-001', 'https://tampered.com', 'MANUAL_ENTRY', 'Tampered',
          'spoofed_sha', '{}', '{}',
          'Unverified', 0.1, '2026-02-01T00:00:00Z',
          'adversary', 0, 'Tampered note', 1
        )
        ON CONFLICT(id) DO UPDATE SET notes = 'Tampered note'
      `).run();
    }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);

    // Confirm original record is untouched
    const record = db.prepare("SELECT * FROM evidence_ledger WHERE id = 'ev-locked-001'").get() as any;
    expect(record.notes).toBe('Original locked note');
    expect(record.content_fingerprint).toBe(fingerprint);
  });

  it('should automatically update updated_at timestamp when mutable tables change', () => {
    runMigrations(db);

    // Insert case with older timestamp
    db.prepare(`
      INSERT INTO cases (id, title, status, priority, is_synthetic, created_at, updated_at)
      VALUES ('c-1', 'Case 1', 'OPEN', 'MEDIUM', 0, '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')
    `).run();

    // Trigger update
    db.prepare("UPDATE cases SET title = 'Case 1 Renamed' WHERE id = 'c-1'").run();

    const updatedCase = db.prepare("SELECT * FROM cases WHERE id = 'c-1'").get() as any;
    expect(updatedCase.title).toBe('Case 1 Renamed');
    expect(updatedCase.updated_at).not.toBe('2025-01-01T00:00:00Z');
  });

  it('should seed deterministic synthetic scenarios and ensure idempotency', () => {
    const res1 = seedDatabase(db);
    expect(res1.seeded).toBe(true);
    expect(res1.counts.cases).toBe(2);
    expect(res1.counts.evidence_ledger).toBe(2);
    expect(res1.counts.entities).toBe(7);
    expect(res1.counts.relationships).toBe(3);
    expect(res1.counts.threat_indicators).toBe(3);

    // Verify synthetic tags
    const arcticCase = db.prepare("SELECT * FROM cases WHERE id = 'case-00000000-0000-0000-0000-000000000001'").get() as any;
    expect(arcticCase.title).toContain('Operation Arctic Phoenix');
    expect(arcticCase.is_synthetic).toBe(1);

    const nexusCase = db.prepare("SELECT * FROM cases WHERE id = 'case-00000000-0000-0000-0000-000000000002'").get() as any;
    expect(nexusCase.title).toContain('Ransomware Nexus');
    expect(nexusCase.is_synthetic).toBe(1);

    // Idempotency: second run should not duplicate records
    const res2 = seedDatabase(db);
    expect(res2.seeded).toBe(false);

    const totalCases = (db.prepare('SELECT COUNT(*) as cnt FROM cases').get() as any).cnt;
    expect(totalCases).toBe(2);
  });

  it('should enforce cascade deletion on entity relationships', () => {
    runMigrations(db);

    db.prepare(`
      INSERT INTO entities (id, name, type, value, risk_score, metadata, is_synthetic)
      VALUES
        ('ent-a', 'Host A', 'IP_ADDRESS', '1.1.1.1', 10, '{}', 0),
        ('ent-b', 'Domain B', 'DOMAIN', 'b.com', 20, '{}', 0)
    `).run();

    db.prepare(`
      INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, status, is_synthetic)
      VALUES ('rel-ab', 'ent-a', 'ent-b', 'RESOLVES_TO', 0.9, 'VERIFIED', 0)
    `).run();

    expect((db.prepare('SELECT COUNT(*) as cnt FROM relationships').get() as any).cnt).toBe(1);

    // Delete ent-a -> rel-ab should cascade delete
    db.prepare("DELETE FROM entities WHERE id = 'ent-a'").run();

    expect((db.prepare('SELECT COUNT(*) as cnt FROM relationships').get() as any).cnt).toBe(0);
  });
});
