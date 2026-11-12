-- Migration: 003_case_workspace_tables.sql
-- Milestone M4 Requirement R4: Case Workspace Tables, Evidence Junction & Notes Immutability Triggers

-- 1. Junction Table for Attaching Pre-Existing Evidence to Cases (Prevents mutating immutable evidence_ledger)
CREATE TABLE IF NOT EXISTS case_evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence_ledger(id) ON DELETE CASCADE,
    attached_by TEXT NOT NULL DEFAULT 'Analyst',
    attached_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    notes TEXT,
    UNIQUE(case_id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_case_evidence_case ON case_evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_case_evidence_evidence ON case_evidence(evidence_id);

-- 2. Append-Only Analyst Notes Table for Cases
CREATE TABLE IF NOT EXISTS case_notes (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author TEXT NOT NULL DEFAULT 'Analyst',
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL, -- SHA-256 fingerprint of note content
    tags TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    parent_note_id TEXT REFERENCES case_notes(id) ON DELETE SET NULL, -- Amendment chain
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_case_notes_parent ON case_notes(parent_note_id);

-- 3. Immutability Triggers for Case Notes (Forensic Auditability)
CREATE TRIGGER IF NOT EXISTS trg_prevent_case_notes_update
BEFORE UPDATE ON case_notes
BEGIN
    SELECT RAISE(FAIL, 'NOTE_IMMUTABILITY_VIOLATION: Analyst notes are immutable forensic audit records and cannot be updated in-place. Create an amendment note referencing parent_note_id.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_case_notes_delete
BEFORE DELETE ON case_notes
BEGIN
    SELECT RAISE(FAIL, 'NOTE_IMMUTABILITY_VIOLATION: Analyst notes cannot be deleted once committed.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_case_notes_replace
BEFORE INSERT ON case_notes
WHEN EXISTS (SELECT 1 FROM case_notes WHERE id = NEW.id)
BEGIN
    SELECT RAISE(FAIL, 'NOTE_IMMUTABILITY_VIOLATION: Overwriting existing analyst notes is prohibited.');
END;

-- 4. Compatibility View for analyst_notes
CREATE VIEW IF NOT EXISTS analyst_notes AS SELECT * FROM case_notes;
