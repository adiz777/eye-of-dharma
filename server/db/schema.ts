// server/db/schema.ts
// Relational Schema DDL & Immutability Triggers for EYE OF DHARMA (EOD)

export const INITIAL_SCHEMA_SQL = `
-- 1. Cases Table
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACTIVE', 'IN_PROGRESS', 'PENDING_REVIEW', 'CLOSED', 'ARCHIVED')),
    priority TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    lead_analyst TEXT NOT NULL DEFAULT 'Analyst',
    tags TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    summary TEXT,
    tlp TEXT NOT NULL DEFAULT 'TLP:AMBER',
    classification TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    closed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_cases_status_priority ON cases(status, priority);
CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);

-- 2. Evidence Ledger Table (Immutable Provenance)
CREATE TABLE IF NOT EXISTS evidence_ledger (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    source_url TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN (
        'USGS_EARTHQUAKE', 'NASA_EONET', 'CISA_KEV', 'CISA_ADVISORY',
        'CRT_SH', 'DNS_RECORD', 'RDAP_REGISTRATION', 'RSS_FEED',
        'MANUAL_ENTRY', 'AGENT_RESEARCH', 'SYNTHETIC_SEED'
    )),
    source_title TEXT NOT NULL,
    content_fingerprint TEXT NOT NULL, -- SHA-256 hex string (64 characters)
    raw_content TEXT NOT NULL, -- Unaltered source payload (JSON/Text)
    parsed_content TEXT, -- Normalized JSON payload
    verification_status TEXT NOT NULL DEFAULT 'Unverified' CHECK (verification_status IN (
        'Observed', 'Source-reported', 'Corroborated', 'Inferred', 'Unverified', 'Stale'
    )),
    confidence_score REAL NOT NULL DEFAULT 0.50 CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    retrieved_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    published_at TEXT,
    recorded_by TEXT NOT NULL DEFAULT 'SYSTEM',
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1)),
    notes TEXT,
    immutable_lock INTEGER NOT NULL DEFAULT 1 CHECK (immutable_lock = 1)
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence_ledger(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_fingerprint ON evidence_ledger(content_fingerprint);
CREATE INDEX IF NOT EXISTS idx_evidence_source_url ON evidence_ledger(source_url);
CREATE INDEX IF NOT EXISTS idx_evidence_retrieved_at ON evidence_ledger(retrieved_at);
CREATE INDEX IF NOT EXISTS idx_evidence_verification ON evidence_ledger(verification_status);

-- 3. Entities Table
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN (
        'DOMAIN', 'IP_ADDRESS', 'EMAIL', 'ACTOR', 'ORGANIZATION',
        'MALWARE', 'VULNERABILITY', 'GEOLOCATION', 'INFRASTRUCTURE',
        'CERTIFICATE', 'CRYPTO_WALLET', 'FILE_HASH'
    )),
    value TEXT NOT NULL, -- Normalized canonical value
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    metadata TEXT NOT NULL DEFAULT '{}', -- JSON object
    first_observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_entities_type_value ON entities(type, value);
CREATE INDEX IF NOT EXISTS idx_entities_case_id ON entities(case_id);
CREATE INDEX IF NOT EXISTS idx_entities_risk_score ON entities(risk_score);

-- 4. Relationships Table (Entity Graph Edges)
CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    source_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL CHECK (relation_type IN (
        'RESOLVES_TO', 'COMMUNICATES_WITH', 'ATTRIBUTED_TO', 'EXPLOITS',
        'HOSTED_ON', 'REGISTERED_BY', 'AFFILIATED_WITH', 'ASSOCIATED_WITH',
        'MENTIONS', 'SUBDOMAIN_OF', 'CERTIFIED_BY'
    )),
    confidence REAL NOT NULL DEFAULT 0.50 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence_id TEXT REFERENCES evidence_ledger(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'INFERRED' CHECK (status IN ('VERIFIED', 'INFERRED', 'HYPOTHESIS')),
    notes TEXT,
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_relationships_evidence ON relationships(evidence_id);
CREATE INDEX IF NOT EXISTS idx_relationships_status ON relationships(status);

-- 5. Threat Indicators Table (IOCs & CTI)
CREATE TABLE IF NOT EXISTS threat_indicators (
    id TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN (
        'IPV4', 'IPV6', 'DOMAIN', 'URL', 'SHA256', 'MD5', 'CVE', 'EMAIL', 'MUTEX'
    )),
    indicator_value TEXT NOT NULL,
    threat_actor TEXT,
    campaign TEXT,
    severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence REAL NOT NULL DEFAULT 0.70 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1)),
    tags TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_threats_type_value ON threat_indicators(indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threat_indicators(severity);
CREATE INDEX IF NOT EXISTS idx_threats_actor ON threat_indicators(threat_actor);
CREATE INDEX IF NOT EXISTS idx_threats_active ON threat_indicators(is_active);

-- 6. Feed Records Table (Public Ingestion Cache)
CREATE TABLE IF NOT EXISTS feed_records (
    id TEXT PRIMARY KEY,
    feed_name TEXT NOT NULL, -- e.g. 'USGS', 'NASA_EONET', 'CISA_KEV', 'CISA_ALERTS', 'CRT_SH', 'RSS'
    external_id TEXT,
    title TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN (
        'EARTHQUAKE', 'HAZARD', 'VULNERABILITY', 'ADVISORY', 'CERTIFICATE', 'NEWS', 'THREAT_INTEL'
    )),
    severity TEXT NOT NULL DEFAULT 'INFO' CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source_url TEXT NOT NULL,
    published_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    summary TEXT,
    payload TEXT NOT NULL, -- JSON string of connector item
    geocoding_lat REAL,
    geocoding_lon REAL,
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_feed_category_published ON feed_records(category, published_at);
CREATE INDEX IF NOT EXISTS idx_feed_source_url ON feed_records(source_url);
CREATE INDEX IF NOT EXISTS idx_feed_severity ON feed_records(severity);
CREATE INDEX IF NOT EXISTS idx_feed_name ON feed_records(feed_name);

-- 7. Watchlists Table
CREATE TABLE IF NOT EXISTS watchlists (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    target_type TEXT NOT NULL CHECK (target_type IN (
        'DOMAIN', 'IP_RANGE', 'CVE', 'KEYWORD', 'ASN', 'ACTOR'
    )),
    pattern TEXT NOT NULL,
    alert_severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (alert_severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    match_count INTEGER NOT NULL DEFAULT 0,
    last_matched_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_synthetic INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_watchlists_active ON watchlists(is_active);
CREATE INDEX IF NOT EXISTS idx_watchlists_type ON watchlists(target_type);

-- 8. Audit Events Table (Tamper-evident System Log)
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL DEFAULT 'SYSTEM',
    action TEXT NOT NULL, -- e.g. CASE_CREATED, EVIDENCE_COMMITTED, SSRF_BLOCKED, AGENT_DISPATCHED
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details TEXT NOT NULL DEFAULT '{}', -- JSON object
    ip_address TEXT,
    user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'SUCCESS' CHECK (status IN ('SUCCESS', 'FAILURE', 'WARNING', 'BLOCKED')),
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor);

-- 9. Agent Runs Table (Multi-Agent Investigation Tracking)
CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    agent_name TEXT NOT NULL CHECK (agent_name IN (
        'DHARMA', 'NETRA', 'CIPHER', 'SENTINEL', 'ATLAS', 'VERITAS', 'SCRIBE'
    )),
    status TEXT NOT NULL DEFAULT 'PLANNED' CHECK (status IN (
        'PLANNED', 'RUNNING', 'VERIFYING', 'COMPLETED', 'FAILED'
    )),
    input_parameters TEXT NOT NULL, -- JSON string
    execution_plan TEXT, -- JSON string representing task tree
    output_summary TEXT,
    token_usage INTEGER NOT NULL DEFAULT 0,
    execution_time_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    citations TEXT NOT NULL DEFAULT '[]', -- JSON array of evidence_ledger(id)
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_case_status ON agent_runs(case_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_runs_agent ON agent_runs(agent_name);

-- 10. Case Evidence Junction Table (Milestone M4)
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

-- 11. Case Notes Table (Milestone M4)
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

-- Compatibility view for analyst_notes
CREATE VIEW IF NOT EXISTS analyst_notes AS SELECT * FROM case_notes;
`;

export const IMMUTABILITY_TRIGGERS_SQL = `
-- Enforce physical immutability invariant on evidence_ledger
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

-- Enforce append-only immutability invariant on case_notes
CREATE TRIGGER IF NOT EXISTS trg_prevent_case_notes_update
BEFORE UPDATE ON case_notes
BEGIN
    SELECT RAISE(FAIL, 'NOTE_IMMUTABILITY_VIOLATION: Analyst notes are immutable forensic audit records and cannot be updated in-place. Create an amendment note referencing parent_note_id.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_case_notes_delete
BEFORE DELETE ON case_notes
BEGIN
    SELECT RAISE(FAIL, 'NOTE_IMMUTABILITY_VIOLATION: Analyst notes cannot be deleted.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_case_notes_replace
BEFORE INSERT ON case_notes
WHEN EXISTS (SELECT 1 FROM case_notes WHERE id = NEW.id)
BEGIN
    SELECT RAISE(FAIL, 'NOTE_IMMUTABILITY_VIOLATION: Note record cannot be replaced or overwritten.');
END;
`;

// Type definitions for DB records
export type CaseStatus = 'OPEN' | 'ACTIVE' | 'IN_PROGRESS' | 'PENDING_REVIEW' | 'CLOSED' | 'ARCHIVED';
export type CasePriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type TlpLevel = 'TLP:WHITE' | 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:AMBER+STRICT' | 'TLP:RED';
export type ClassificationLevel = 'UNCLASSIFIED' | 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET';

export interface CaseRecord {
  id: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  priority: CasePriority;
  lead_analyst: string;
  tags: string;
  summary: string | null;
  tlp?: string;
  classification?: string;
  is_synthetic: number;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface CaseEvidenceRecord {
  id: string;
  case_id: string;
  evidence_id: string;
  attached_by: string;
  attached_at: string;
  notes: string | null;
}

export interface CaseNoteRecord {
  id: string;
  case_id: string;
  author: string;
  content: string;
  content_hash: string;
  tags: string;
  parent_note_id: string | null;
  version: number;
  created_at: string;
  is_synthetic: number;
}

export type SourceType =
  | 'USGS_EARTHQUAKE'
  | 'NASA_EONET'
  | 'CISA_KEV'
  | 'CISA_ADVISORY'
  | 'CRT_SH'
  | 'DNS_RECORD'
  | 'RDAP_REGISTRATION'
  | 'RSS_FEED'
  | 'MANUAL_ENTRY'
  | 'AGENT_RESEARCH'
  | 'SYNTHETIC_SEED';

export type VerificationStatus =
  | 'Observed'
  | 'Source-reported'
  | 'Corroborated'
  | 'Inferred'
  | 'Unverified'
  | 'Stale';

export interface EvidenceRecord {
  id: string;
  case_id: string | null;
  source_url: string;
  source_type: SourceType;
  source_title: string;
  content_fingerprint: string;
  raw_content: string;
  parsed_content: string | null;
  verification_status: VerificationStatus;
  confidence_score: number;
  retrieved_at: string;
  published_at: string | null;
  recorded_by: string;
  is_synthetic: number;
  notes: string | null;
  immutable_lock: number;
}

export type EntityType =
  | 'DOMAIN'
  | 'IP_ADDRESS'
  | 'EMAIL'
  | 'ACTOR'
  | 'ORGANIZATION'
  | 'MALWARE'
  | 'VULNERABILITY'
  | 'GEOLOCATION'
  | 'INFRASTRUCTURE'
  | 'CERTIFICATE'
  | 'CRYPTO_WALLET'
  | 'FILE_HASH';

export interface EntityRecord {
  id: string;
  case_id: string | null;
  name: string;
  type: EntityType;
  value: string;
  risk_score: number;
  metadata: string;
  first_observed_at: string;
  last_observed_at: string;
  is_synthetic: number;
  created_at: string;
  updated_at: string;
}

export type RelationType =
  | 'RESOLVES_TO'
  | 'COMMUNICATES_WITH'
  | 'ATTRIBUTED_TO'
  | 'EXPLOITS'
  | 'HOSTED_ON'
  | 'REGISTERED_BY'
  | 'AFFILIATED_WITH'
  | 'ASSOCIATED_WITH'
  | 'MENTIONS'
  | 'SUBDOMAIN_OF'
  | 'CERTIFIED_BY';

export type RelationStatus = 'VERIFIED' | 'INFERRED' | 'HYPOTHESIS';

export interface RelationshipRecord {
  id: string;
  source_entity_id: string;
  target_entity_id: string;
  relation_type: RelationType;
  confidence: number;
  evidence_id: string | null;
  status: RelationStatus;
  notes: string | null;
  is_synthetic: number;
  created_at: string;
}

export type IndicatorType = 'IPV4' | 'IPV6' | 'DOMAIN' | 'URL' | 'SHA256' | 'MD5' | 'CVE' | 'EMAIL' | 'MUTEX';
export type IndicatorSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ThreatIndicatorRecord {
  id: string;
  indicator_type: IndicatorType;
  indicator_value: string;
  threat_actor: string | null;
  campaign: string | null;
  severity: IndicatorSeverity;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  is_active: number;
  is_synthetic: number;
  tags: string;
  description: string | null;
  created_at: string;
}

export type FeedCategory = 'EARTHQUAKE' | 'HAZARD' | 'VULNERABILITY' | 'ADVISORY' | 'CERTIFICATE' | 'NEWS' | 'THREAT_INTEL';
export type FeedSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface FeedRecord {
  id: string;
  feed_name: string;
  external_id: string | null;
  title: string;
  category: FeedCategory;
  severity: FeedSeverity;
  source_url: string;
  published_at: string;
  ingested_at: string;
  summary: string | null;
  payload: string;
  geocoding_lat: number | null;
  geocoding_lon: number | null;
  is_synthetic: number;
}

export type WatchlistTargetType = 'DOMAIN' | 'IP_RANGE' | 'CVE' | 'KEYWORD' | 'ASN' | 'ACTOR';

export interface WatchlistRecord {
  id: string;
  name: string;
  description: string | null;
  target_type: WatchlistTargetType;
  pattern: string;
  alert_severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  is_active: number;
  match_count: number;
  last_matched_at: string | null;
  created_at: string;
  updated_at: string;
  is_synthetic: number;
}

export type AuditStatus = 'SUCCESS' | 'FAILURE' | 'WARNING' | 'BLOCKED';

export interface AuditEventRecord {
  id: string;
  actor: string;
  action: string;
  entity_type: string;
  entity_id: string | null;
  details: string;
  ip_address: string | null;
  user_agent: string | null;
  status: AuditStatus;
  timestamp: string;
}

export type AgentName = 'DHARMA' | 'NETRA' | 'CIPHER' | 'SENTINEL' | 'ATLAS' | 'VERITAS' | 'SCRIBE';
export type AgentStatus = 'PLANNED' | 'RUNNING' | 'VERIFYING' | 'COMPLETED' | 'FAILED';

export interface AgentRunRecord {
  id: string;
  case_id: string | null;
  agent_name: AgentName;
  status: AgentStatus;
  input_parameters: string;
  execution_plan: string | null;
  output_summary: string | null;
  token_usage: number;
  execution_time_ms: number;
  error_message: string | null;
  citations: string;
  started_at: string;
  completed_at: string | null;
}
