-- Migration: 001_initial_schema.sql
-- Description: Core 9 tables for EYE OF DHARMA Operations Platform

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
