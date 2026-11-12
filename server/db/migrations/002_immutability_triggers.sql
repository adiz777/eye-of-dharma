-- Migration: 002_immutability_triggers.sql
-- Enforce read-only / append-only invariant on evidence_ledger

CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_update
BEFORE UPDATE ON evidence_ledger
BEGIN
    SELECT RAISE(FAIL, 'EVIDENCE_IMMUTABILITY_VIOLATION: Entries in evidence_ledger are cryptographically fingerprinted and immutable. Modifications are prohibited.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_delete
BEFORE DELETE ON evidence_ledger
BEGIN
    SELECT RAISE(FAIL, 'EVIDENCE_IMMUTABILITY_VIOLATION: Entries in evidence_ledger cannot be deleted once recorded.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_replace
BEFORE INSERT ON evidence_ledger
WHEN EXISTS (SELECT 1 FROM evidence_ledger WHERE id = NEW.id)
BEGIN
    SELECT RAISE(FAIL, 'EVIDENCE_IMMUTABILITY_VIOLATION: Entries in evidence_ledger cannot be replaced or overwritten.');
END;

-- Automatic updated_at timestamps for mutable entities
CREATE TRIGGER IF NOT EXISTS trg_cases_updated_at
AFTER UPDATE ON cases
FOR EACH ROW
WHEN (NEW.updated_at IS OLD.updated_at AND NEW.updated_at IS NOT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
BEGIN
    UPDATE cases SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_entities_updated_at
AFTER UPDATE ON entities
FOR EACH ROW
WHEN (NEW.updated_at IS OLD.updated_at AND NEW.updated_at IS NOT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
BEGIN
    UPDATE entities SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_watchlists_updated_at
AFTER UPDATE ON watchlists
FOR EACH ROW
WHEN (NEW.updated_at IS OLD.updated_at AND NEW.updated_at IS NOT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
BEGIN
    UPDATE watchlists SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = OLD.id;
END;
