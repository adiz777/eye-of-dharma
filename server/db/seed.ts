// server/db/seed.ts
// Deterministic synthetic seed data for EYE OF DHARMA (EOD)
// Scenarios: "Operation Arctic Phoenix" and "Ransomware Nexus 2026"

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { getDatabase } from './connection.js';
import { runMigrations } from './migrate.js';

export function computeSha256(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function seedDatabase(db: Database.Database): { seeded: boolean; counts: Record<string, number> } {
  // Ensure tables and triggers are ready
  runMigrations(db);

  // Check if synthetic seed already exists (idempotent)
  const existingCase = db.prepare('SELECT id FROM cases WHERE id = ?').get('case-00000000-0000-0000-0000-000000000001');
  if (existingCase) {
    const counts = getSyntheticCounts(db);
    return { seeded: false, counts };
  }

  db.transaction(() => {
    // 1. Cases
    const insertCase = db.prepare(`
      INSERT INTO cases (id, title, description, status, priority, lead_analyst, tags, summary, is_synthetic, created_at, updated_at)
      VALUES (@id, @title, @description, @status, @priority, @lead_analyst, @tags, @summary, @is_synthetic, @created_at, @updated_at)
    `);

    insertCase.run({
      id: 'case-00000000-0000-0000-0000-000000000001',
      title: 'Operation Arctic Phoenix - Grid Infiltration',
      description: 'Advanced Persistent Threat (APT) targeting European and Nordic renewable energy SCADA infrastructure.',
      status: 'ACTIVE',
      priority: 'CRITICAL',
      lead_analyst: 'Senior Agent Vance',
      tags: JSON.stringify(['APT-44', 'SCADA', 'ENERGY', 'ZERO-DAY']),
      summary: 'Observed lateral movement attempts across Nordic wind farm SCADA telemetry endpoints.',
      is_synthetic: 1,
      created_at: '2026-01-15T08:30:00.000Z',
      updated_at: '2026-01-15T08:30:00.000Z'
    });

    insertCase.run({
      id: 'case-00000000-0000-0000-0000-000000000002',
      title: 'Ransomware Nexus 2026 Syndicate',
      description: 'Double-extortion cybercrime syndicate operating darknet leak mirrors and exfiltrating proprietary CAD files.',
      status: 'OPEN',
      priority: 'HIGH',
      lead_analyst: 'Special Agent Chen',
      tags: JSON.stringify(['RANSOMWARE', 'TOR', 'EXFILTRATION']),
      summary: 'Tracking darknet exfiltration sites and cryptocurrency ransom wallets associated with Nexus Locker.',
      is_synthetic: 1,
      created_at: '2026-01-18T14:15:00.000Z',
      updated_at: '2026-01-18T14:15:00.000Z'
    });

    // 2. Evidence Ledger
    const insertEvidence = db.prepare(`
      INSERT INTO evidence_ledger (
        id, case_id, source_url, source_type, source_title,
        content_fingerprint, raw_content, parsed_content,
        verification_status, confidence_score, retrieved_at,
        published_at, recorded_by, is_synthetic, notes, immutable_lock
      ) VALUES (
        @id, @case_id, @source_url, @source_type, @source_title,
        @content_fingerprint, @raw_content, @parsed_content,
        @verification_status, @confidence_score, @retrieved_at,
        @published_at, @recorded_by, @is_synthetic, @notes, 1
      )
    `);

    const ev1Raw = JSON.stringify({
      advisory_id: 'AA26-081A',
      threat_group: 'APT-44',
      sector: 'Energy',
      vulnerabilities: ['CVE-2026-1189'],
      iocs: ['195.140.228.17', 'scada-telemetry-portal.nordic-power.net']
    });

    insertEvidence.run({
      id: 'ev-00000000-0000-0000-0000-000000000001',
      case_id: 'case-00000000-0000-0000-0000-000000000001',
      source_url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-081a',
      source_type: 'CISA_ADVISORY',
      source_title: 'AA26-081A: APT Targeting of Critical Energy Infrastructure SCADA Networks',
      content_fingerprint: computeSha256(ev1Raw),
      raw_content: ev1Raw,
      parsed_content: JSON.stringify({ actor: 'APT-44', target: 'SCADA', severity: 'CRITICAL' }),
      verification_status: 'Source-reported',
      confidence_score: 0.95,
      retrieved_at: '2026-01-15T09:00:00.000Z',
      published_at: '2026-01-14T20:00:00.000Z',
      recorded_by: 'SENTINEL',
      is_synthetic: 1,
      notes: 'Authoritative advisory release from CISA regarding renewable grid targeting.'
    });

    const ev2Raw = JSON.stringify({
      query: 'scada-telemetry-portal.nordic-power.net',
      subject: 'CN=scada-telemetry-portal.nordic-power.net',
      issuer: "Let's Encrypt Authority X3",
      serial_number: '04a1b2c3d4e5f6',
      not_before: '2026-01-10T00:00:00Z',
      not_after: '2026-04-10T00:00:00Z'
    });

    insertEvidence.run({
      id: 'ev-00000000-0000-0000-0000-000000000002',
      case_id: 'case-00000000-0000-0000-0000-000000000001',
      source_url: 'https://crt.sh/?q=scada-telemetry-portal.nordic-power.net',
      source_type: 'CRT_SH',
      source_title: 'Certificate Transparency Log: scada-telemetry-portal.nordic-power.net',
      content_fingerprint: computeSha256(ev2Raw),
      raw_content: ev2Raw,
      parsed_content: JSON.stringify({ domain: 'scada-telemetry-portal.nordic-power.net', valid: true }),
      verification_status: 'Observed',
      confidence_score: 0.98,
      retrieved_at: '2026-01-15T09:15:00.000Z',
      published_at: '2026-01-10T00:00:00.000Z',
      recorded_by: 'NETRA',
      is_synthetic: 1,
      notes: 'CT log discovery proves certificate was provisioned 5 days prior to attack wave.'
    });

    // 3. Entities
    const insertEntity = db.prepare(`
      INSERT INTO entities (
        id, case_id, name, type, value, risk_score, metadata,
        first_observed_at, last_observed_at, is_synthetic, created_at, updated_at
      ) VALUES (
        @id, @case_id, @name, @type, @value, @risk_score, @metadata,
        @first_observed_at, @last_observed_at, @is_synthetic, @created_at, @updated_at
      )
    `);

    insertEntity.run({
      id: 'ent-00000000-0000-0000-0000-000000000001',
      case_id: 'case-00000000-0000-0000-0000-000000000001',
      name: 'APT-44 (Arctic Phoenix)',
      type: 'ACTOR',
      value: 'APT-44',
      risk_score: 95,
      metadata: JSON.stringify({ origin: 'Eastern Europe / Eurasia', motivation: 'Sabotage & Geopolitical Leverage' }),
      first_observed_at: '2026-01-14T20:00:00.000Z',
      last_observed_at: '2026-01-15T09:00:00.000Z',
      is_synthetic: 1,
      created_at: '2026-01-15T09:00:00.000Z',
      updated_at: '2026-01-15T09:00:00.000Z'
    });

    insertEntity.run({
      id: 'ent-00000000-0000-0000-0000-000000000002',
      case_id: 'case-00000000-0000-0000-0000-000000000001',
      name: 'scada-telemetry-portal.nordic-power.net',
      type: 'DOMAIN',
      value: 'scada-telemetry-portal.nordic-power.net',
      risk_score: 88,
      metadata: JSON.stringify({ registrar: 'NameCheap (Simulated)', nameservers: ['ns1.nordic-power.net'] }),
      first_observed_at: '2026-01-10T00:00:00.000Z',
      last_observed_at: '2026-01-15T09:15:00.000Z',
      is_synthetic: 1,
      created_at: '2026-01-15T09:15:00.000Z',
      updated_at: '2026-01-15T09:15:00.000Z'
    });

    insertEntity.run({
      id: 'ent-00000000-0000-0000-0000-000000000003',
      case_id: 'case-00000000-0000-0000-0000-000000000001',
      name: '195.140.228.17',
      type: 'IP_ADDRESS',
      value: '195.140.228.17',
      risk_score: 90,
      metadata: JSON.stringify({ asn: 'AS44123', country: 'RU', isp: 'HostKey Satellite Network' }),
      first_observed_at: '2026-01-14T20:00:00.000Z',
      last_observed_at: '2026-01-15T09:15:00.000Z',
      is_synthetic: 1,
      created_at: '2026-01-15T09:15:00.000Z',
      updated_at: '2026-01-15T09:15:00.000Z'
    });

    insertEntity.run({
      id: 'ent-00000000-0000-0000-0000-000000000004',
      case_id: 'case-00000000-0000-0000-0000-000000000001',
      name: 'CVE-2026-1189',
      type: 'VULNERABILITY',
      value: 'CVE-2026-1189',
      risk_score: 98,
      metadata: JSON.stringify({ cvss: 9.8, component: 'Modbus TCP Daemon', type: 'Remote Code Execution' }),
      first_observed_at: '2026-01-14T20:00:00.000Z',
      last_observed_at: '2026-01-15T09:00:00.000Z',
      is_synthetic: 1,
      created_at: '2026-01-15T09:00:00.000Z',
      updated_at: '2026-01-15T09:00:00.000Z'
    });

    // Scenario 2 Entities
    insertEntity.run({
      id: 'ent-00000000-0000-0000-0000-000000000005',
      case_id: 'case-00000000-0000-0000-0000-000000000002',
      name: 'Nexus Locker Group',
      type: 'ACTOR',
      value: 'Nexus Locker',
      risk_score: 85,
      metadata: JSON.stringify({ ransom_demands_avg_btc: 4.5, encryption_algo: 'ChaCha20-Poly1305' }),
      first_observed_at: '2026-01-18T14:15:00.000Z',
      last_observed_at: '2026-01-18T14:15:00.000Z',
      is_synthetic: 1,
      created_at: '2026-01-18T14:15:00.000Z',
      updated_at: '2026-01-18T14:15:00.000Z'
    });

    insertEntity.run({
      id: 'ent-00000000-0000-0000-0000-000000000006',
      case_id: 'case-00000000-0000-0000-0000-000000000002',
      name: 'nexus-leaks-portal.onion',
      type: 'DOMAIN',
      value: 'nexus-leaks-portal.onion',
      risk_score: 75,
      metadata: JSON.stringify({ network: 'Tor Onion v3', status: 'ONLINE' }),
      first_observed_at: '2026-01-18T14:15:00.000Z',
      last_observed_at: '2026-01-18T14:15:00.000Z',
      is_synthetic: 1,
      created_at: '2026-01-18T14:15:00.000Z',
      updated_at: '2026-01-18T14:15:00.000Z'
    });

    insertEntity.run({
      id: 'ent-00000000-0000-0000-0000-000000000007',
      case_id: 'case-00000000-0000-0000-0000-000000000002',
      name: '185.220.101.5',
      type: 'IP_ADDRESS',
      value: '185.220.101.5',
      risk_score: 65,
      metadata: JSON.stringify({ role: 'Tor Exit Node', asn: 'AS208323', country: 'DE' }),
      first_observed_at: '2026-01-18T14:15:00.000Z',
      last_observed_at: '2026-01-18T14:15:00.000Z',
      is_synthetic: 1,
      created_at: '2026-01-18T14:15:00.000Z',
      updated_at: '2026-01-18T14:15:00.000Z'
    });

    // 4. Relationships
    const insertRelationship = db.prepare(`
      INSERT INTO relationships (
        id, source_entity_id, target_entity_id, relation_type, confidence,
        evidence_id, status, notes, is_synthetic, created_at
      ) VALUES (
        @id, @source_entity_id, @target_entity_id, @relation_type, @confidence,
        @evidence_id, @status, @notes, @is_synthetic, @created_at
      )
    `);

    insertRelationship.run({
      id: 'rel-00000000-0000-0000-0000-000000000001',
      source_entity_id: 'ent-00000000-0000-0000-0000-000000000001',
      target_entity_id: 'ent-00000000-0000-0000-0000-000000000002',
      relation_type: 'ATTRIBUTED_TO',
      confidence: 0.92,
      evidence_id: 'ev-00000000-0000-0000-0000-000000000001',
      status: 'VERIFIED',
      notes: 'C2 domain attribution confirmed via advisory AA26-081A.',
      is_synthetic: 1,
      created_at: '2026-01-15T09:20:00.000Z'
    });

    insertRelationship.run({
      id: 'rel-00000000-0000-0000-0000-000000000002',
      source_entity_id: 'ent-00000000-0000-0000-0000-000000000002',
      target_entity_id: 'ent-00000000-0000-0000-0000-000000000003',
      relation_type: 'RESOLVES_TO',
      confidence: 0.99,
      evidence_id: 'ev-00000000-0000-0000-0000-000000000002',
      status: 'VERIFIED',
      notes: 'A record resolution confirmed via DNS telemetry.',
      is_synthetic: 1,
      created_at: '2026-01-15T09:20:00.000Z'
    });

    insertRelationship.run({
      id: 'rel-00000000-0000-0000-0000-000000000003',
      source_entity_id: 'ent-00000000-0000-0000-0000-000000000001',
      target_entity_id: 'ent-00000000-0000-0000-0000-000000000004',
      relation_type: 'EXPLOITS',
      confidence: 0.85,
      evidence_id: 'ev-00000000-0000-0000-0000-000000000001',
      status: 'VERIFIED',
      notes: 'Exploitation vector documented in initial telemetry.',
      is_synthetic: 1,
      created_at: '2026-01-15T09:20:00.000Z'
    });

    // 5. Threat Indicators
    const insertThreat = db.prepare(`
      INSERT INTO threat_indicators (
        id, indicator_type, indicator_value, threat_actor, campaign,
        severity, confidence, source, first_seen, last_seen, is_active,
        is_synthetic, tags, description, created_at
      ) VALUES (
        @id, @indicator_type, @indicator_value, @threat_actor, @campaign,
        @severity, @confidence, @source, @first_seen, @last_seen, @is_active,
        @is_synthetic, @tags, @description, @created_at
      )
    `);

    insertThreat.run({
      id: 'thr-00000000-0000-0000-0000-000000000001',
      indicator_type: 'DOMAIN',
      indicator_value: 'scada-telemetry-portal.nordic-power.net',
      threat_actor: 'APT-44',
      campaign: 'Operation Arctic Phoenix',
      severity: 'HIGH',
      confidence: 0.90,
      source: 'CISA_ADVISORY',
      first_seen: '2026-01-10T00:00:00.000Z',
      last_seen: '2026-01-15T09:15:00.000Z',
      is_active: 1,
      is_synthetic: 1,
      tags: JSON.stringify(['C2', 'SCADA']),
      description: 'Active C2 host disguised as legitimate telemetry portal.',
      created_at: '2026-01-15T09:30:00.000Z'
    });

    insertThreat.run({
      id: 'thr-00000000-0000-0000-0000-000000000002',
      indicator_type: 'IPV4',
      indicator_value: '195.140.228.17',
      threat_actor: 'APT-44',
      campaign: 'Operation Arctic Phoenix',
      severity: 'CRITICAL',
      confidence: 0.95,
      source: 'EOD_NETRA',
      first_seen: '2026-01-14T20:00:00.000Z',
      last_seen: '2026-01-15T09:15:00.000Z',
      is_active: 1,
      is_synthetic: 1,
      tags: JSON.stringify(['C2_INFRASTRUCTURE', 'RUSSIAN_FEDERATION']),
      description: 'Primary ingress point for Modbus exploitation payloads.',
      created_at: '2026-01-15T09:30:00.000Z'
    });

    insertThreat.run({
      id: 'thr-00000000-0000-0000-0000-000000000003',
      indicator_type: 'CVE',
      indicator_value: 'CVE-2026-1189',
      threat_actor: 'APT-44',
      campaign: 'Operation Arctic Phoenix',
      severity: 'CRITICAL',
      confidence: 0.98,
      source: 'CISA_KEV',
      first_seen: '2026-01-14T00:00:00.000Z',
      last_seen: '2026-01-15T09:00:00.000Z',
      is_active: 1,
      is_synthetic: 1,
      tags: JSON.stringify(['KEV', 'SCADA_RCE']),
      description: 'Zero-day vulnerability in industrial Modbus protocol implementations.',
      created_at: '2026-01-15T09:30:00.000Z'
    });

    // 6. Feed Records
    const insertFeed = db.prepare(`
      INSERT INTO feed_records (
        id, feed_name, external_id, title, category, severity,
        source_url, published_at, ingested_at, summary, payload,
        geocoding_lat, geocoding_lon, is_synthetic
      ) VALUES (
        @id, @feed_name, @external_id, @title, @category, @severity,
        @source_url, @published_at, @ingested_at, @summary, @payload,
        @geocoding_lat, @geocoding_lon, @is_synthetic
      )
    `);

    insertFeed.run({
      id: 'feed-00000000-0000-0000-0000-000000000001',
      feed_name: 'CISA_ALERTS',
      external_id: 'AA26-081A',
      title: 'Alert AA26-081A: Arctic Phoenix Exploitation of Energy SCADA Networks',
      category: 'ADVISORY',
      severity: 'CRITICAL',
      source_url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-081a',
      published_at: '2026-01-14T20:00:00.000Z',
      ingested_at: '2026-01-15T09:00:00.000Z',
      summary: 'Advisory covering exploitation of CVE-2026-1189 in renewable power grids.',
      payload: JSON.stringify({ title: 'AA26-081A', severity: 'CRITICAL', sector: 'Energy' }),
      geocoding_lat: 60.1699,
      geocoding_lon: 24.9384,
      is_synthetic: 1
    });

    insertFeed.run({
      id: 'feed-00000000-0000-0000-0000-000000000002',
      feed_name: 'USGS',
      external_id: 'us7000m99z',
      title: 'M 5.8 Earthquake - 42 km ENE of Reykjavik, Iceland',
      category: 'EARTHQUAKE',
      severity: 'MEDIUM',
      source_url: 'https://earthquake.usgs.gov/earthquakes/eventpage/us7000m99z',
      published_at: '2026-01-15T04:22:11.000Z',
      ingested_at: '2026-01-15T05:00:00.000Z',
      summary: 'Seismic event detected near geothermal power plant cluster.',
      payload: JSON.stringify({ mag: 5.8, place: 'Reykjavik region', depth_km: 10.2 }),
      geocoding_lat: 64.1466,
      geocoding_lon: -21.9426,
      is_synthetic: 1
    });

    // 7. Watchlists
    const insertWatchlist = db.prepare(`
      INSERT INTO watchlists (
        id, name, description, target_type, pattern, alert_severity,
        is_active, match_count, last_matched_at, created_at, updated_at, is_synthetic
      ) VALUES (
        @id, @name, @description, @target_type, @pattern, @alert_severity,
        @is_active, @match_count, @last_matched_at, @created_at, @updated_at, @is_synthetic
      )
    `);

    insertWatchlist.run({
      id: 'wl-00000000-0000-0000-0000-000000000001',
      name: 'APT-44 C2 Infrastructure Watch',
      description: 'Monitors incoming DNS queries and feed items for known APT-44 patterns.',
      target_type: 'DOMAIN',
      pattern: '*.nordic-power.net',
      alert_severity: 'HIGH',
      is_active: 1,
      match_count: 3,
      last_matched_at: '2026-01-15T09:15:00.000Z',
      created_at: '2026-01-15T08:00:00.000Z',
      updated_at: '2026-01-15T09:15:00.000Z',
      is_synthetic: 1
    });

    insertWatchlist.run({
      id: 'wl-00000000-0000-0000-0000-000000000002',
      name: 'Critical SCADA Vulnerability Alerts',
      description: 'Alerts analysts whenever a critical SCADA or Modbus CVE is reported.',
      target_type: 'CVE',
      pattern: 'CVE-2026-*',
      alert_severity: 'CRITICAL',
      is_active: 1,
      match_count: 1,
      last_matched_at: '2026-01-15T09:00:00.000Z',
      created_at: '2026-01-15T08:00:00.000Z',
      updated_at: '2026-01-15T09:00:00.000Z',
      is_synthetic: 1
    });

    // 8. Audit Events
    const insertAudit = db.prepare(`
      INSERT INTO audit_events (
        id, actor, action, entity_type, entity_id, details, ip_address, user_agent, status, timestamp
      ) VALUES (
        @id, @actor, @action, @entity_type, @entity_id, @details, @ip_address, @user_agent, @status, @timestamp
      )
    `);

    insertAudit.run({
      id: 'aud-00000000-0000-0000-0000-000000000001',
      actor: 'SYSTEM',
      action: 'SEED_DATA_INITIALIZED',
      entity_type: 'SYSTEM',
      entity_id: 'SYSTEM_BOOT',
      details: JSON.stringify({ scenarios: ['Operation Arctic Phoenix', 'Ransomware Nexus 2026'], mode: 'deterministic' }),
      ip_address: '127.0.0.1',
      user_agent: 'EOD-Bootstrap/1.0',
      status: 'SUCCESS',
      timestamp: '2026-01-15T08:00:00.000Z'
    });

    insertAudit.run({
      id: 'aud-00000000-0000-0000-0000-000000000002',
      actor: 'Analyst Vance',
      action: 'CASE_CREATED',
      entity_type: 'CASE',
      entity_id: 'case-00000000-0000-0000-0000-000000000001',
      details: JSON.stringify({ priority: 'CRITICAL', title: 'Operation Arctic Phoenix - Grid Infiltration' }),
      ip_address: '10.200.1.42',
      user_agent: 'Mozilla/5.0 (EOD-Console)',
      status: 'SUCCESS',
      timestamp: '2026-01-15T08:30:00.000Z'
    });

    // 9. Agent Runs
    const insertAgentRun = db.prepare(`
      INSERT INTO agent_runs (
        id, case_id, agent_name, status, input_parameters, execution_plan,
        output_summary, token_usage, execution_time_ms, error_message, citations, started_at, completed_at
      ) VALUES (
        @id, @case_id, @agent_name, @status, @input_parameters, @execution_plan,
        @output_summary, @token_usage, @execution_time_ms, @error_message, @citations, @started_at, @completed_at
      )
    `);

    insertAgentRun.run({
      id: 'run-00000000-0000-0000-0000-000000000001',
      case_id: 'case-00000000-0000-0000-0000-000000000001',
      agent_name: 'DHARMA',
      status: 'COMPLETED',
      input_parameters: JSON.stringify({ goal: 'Investigate SCADA intrusion vectors in Nordic power grid' }),
      execution_plan: JSON.stringify({
        steps: [
          { agent: 'NETRA', task: 'Scan CT logs for *.nordic-power.net' },
          { agent: 'SENTINEL', task: 'Cross-reference CISA advisories for Modbus CVEs' },
          { agent: 'VERITAS', task: 'Verify IP and domain attribution' }
        ]
      }),
      output_summary: 'Identified active C2 telemetry portal and tied IP 195.140.228.17 to APT-44 campaigns.',
      token_usage: 1240,
      execution_time_ms: 3420,
      error_message: null,
      citations: JSON.stringify(['ev-00000000-0000-0000-0000-000000000001', 'ev-00000000-0000-0000-0000-000000000002']),
      started_at: '2026-01-15T09:00:00.000Z',
      completed_at: '2026-01-15T09:00:03.420Z'
    });
  })();

  const counts = getSyntheticCounts(db);
  return { seeded: true, counts };
}

export function getSyntheticCounts(db: Database.Database): Record<string, number> {
  const tables = ['cases', 'evidence_ledger', 'entities', 'relationships', 'threat_indicators', 'feed_records', 'watchlists'];
  const counts: Record<string, number> = {};
  for (const table of tables) {
    const row = db.prepare(`SELECT COUNT(*) as cnt FROM ${table} WHERE is_synthetic = 1`).get() as { cnt: number };
    counts[table] = row.cnt;
  }
  return counts;
}

// CLI runner if executed directly
if (process.argv[1]?.includes('seed')) {
  try {
    const db = getDatabase();
    console.log('[EOD Database] Seeding deterministic synthetic scenarios...');
    const result = seedDatabase(db);
    console.log('[EOD Database] Seeding finished:', result);
    process.exit(0);
  } catch (err) {
    console.error('[EOD Database] Seeding failed:', err);
    process.exit(1);
  }
}
