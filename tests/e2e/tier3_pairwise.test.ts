/**
 * EYE OF DHARMA (EOD) — E2E Test Suite: Tier 3 (Cross-Feature Combinations)
 * 5 complete pairwise data pipelines connecting multi-module capabilities.
 */

import {
  TestCase,
  assert,
  assertEqual,
  assertIncludes,
  computeSha256,
  createInMemoryDatabase,
  evaluateTerminalCommand,
  AgentStateMachine,
  auditCitationsAgainstLedger,
  validateStixBundle,
  validateCsvFormat,
  validateHtmlReport
} from './helpers.js';

export const tier3Tests: TestCase[] = [
  // --------------------------------------------------------------------------
  // Pipeline 1: Ingestion -> Evidence Ledger -> Entity/Relationship Graph -> Case Linkage
  // --------------------------------------------------------------------------
  {
    name: 'T3_01_pipeline_ingestion_to_evidence_graph_and_case',
    tier: 3,
    area: 'Pairwise Pipelines',
    fn: () => {
      const db = createInMemoryDatabase();

      // Step 1: Create Case
      const caseId = 'case-pair-01';
      db.prepare(`
        INSERT INTO cases (id, title, priority, status)
        VALUES (?, 'Operation Deep Freeze', 'HIGH', 'ACTIVE')
      `).run(caseId);

      // Step 2: Ingest CISA KEV Feed Item into Evidence Ledger
      const rawCisaItem = JSON.stringify({
        cveID: 'CVE-2026-9001',
        vendorProject: 'NordicSCADA',
        product: 'PowerGrid Controller',
        vulnerabilityName: 'Authentication Bypass',
        dateAdded: '2026-10-28',
        knownRansomwareCampaignUse: 'Known'
      });
      const evidenceId = 'ev-pair-01';
      const fingerprint = computeSha256(rawCisaItem);

      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score
        ) VALUES (?, ?, 'https://cisa.gov/kev/2026-9001', 'CISA_KEV', 'CISA KEV Alert', ?, ?, 'Observed', 1.0)
      `).run(evidenceId, caseId, fingerprint, rawCisaItem);

      // Step 3: Extract & Tag Entities linked to Case
      const actorEntityId = 'ent-actor-01';
      const vulnEntityId = 'ent-vuln-01';
      db.prepare(`
        INSERT INTO entities (id, case_id, name, type, value, risk_score)
        VALUES (?, ?, 'Threat Actor Boreas', 'ACTOR', 'Boreas', 90)
      `).run(actorEntityId, caseId);

      db.prepare(`
        INSERT INTO entities (id, case_id, name, type, value, risk_score)
        VALUES (?, ?, 'CVE-2026-9001', 'VULNERABILITY', 'CVE-2026-9001', 95)
      `).run(vulnEntityId, caseId);

      // Step 4: Create Relationship referencing Evidence Ledger
      const relId = 'rel-pair-01';
      db.prepare(`
        INSERT INTO relationships (
          id, source_entity_id, target_entity_id, relation_type,
          confidence, evidence_id, status
        ) VALUES (?, ?, ?, 'EXPLOITS', 0.95, ?, 'VERIFIED')
      `).run(relId, actorEntityId, vulnEntityId, evidenceId);

      // Step 5: Verification of cross-table relational integrity
      const joined = db.prepare(`
        SELECT 
          c.title as case_title,
          e.content_fingerprint,
          r.relation_type,
          r.status as rel_status,
          src.name as source_name,
          tgt.name as target_name
        FROM relationships r
        JOIN evidence_ledger e ON r.evidence_id = e.id
        JOIN cases c ON e.case_id = c.id
        JOIN entities src ON r.source_entity_id = src.id
        JOIN entities tgt ON r.target_entity_id = tgt.id
        WHERE r.id = ?
      `).get(relId) as any;

      assert(joined !== undefined, 'Cross-table join returned empty set');
      assertEqual(joined.case_title, 'Operation Deep Freeze');
      assertEqual(joined.content_fingerprint, fingerprint);
      assertEqual(joined.relation_type, 'EXPLOITS');
      assertEqual(joined.rel_status, 'VERIFIED');
      assertEqual(joined.source_name, 'Threat Actor Boreas');
      assertEqual(joined.target_name, 'CVE-2026-9001');

      db.close();
    }
  },

  // --------------------------------------------------------------------------
  // Pipeline 2: Case Creation -> Passive Footprint -> Provenance -> Custody Audit
  // --------------------------------------------------------------------------
  {
    name: 'T3_02_pipeline_footprint_to_evidence_and_custody_audit',
    tier: 3,
    area: 'Pairwise Pipelines',
    fn: () => {
      const db = createInMemoryDatabase();

      // Step 1: Open Case
      const caseId = 'case-custody-02';
      db.prepare("INSERT INTO cases (id, title, priority) VALUES (?, 'Recon Case', 'MEDIUM')").run(caseId);

      // Step 2: Log Audit Event for Case Creation
      db.prepare(`
        INSERT INTO audit_events (id, actor, action, entity_type, entity_id, status)
        VALUES ('aud-01', 'Analyst Vance', 'CASE_CREATED', 'CASE', ?, 'SUCCESS')
      `).run(caseId);

      // Step 3: Perform Passive Footprint Query & Save to Evidence Ledger
      const domainTarget = 'telemetry-grid.org';
      const dnsRawPayload = JSON.stringify({
        domain: domainTarget,
        records: [
          { type: 'A', value: '195.140.228.17', ttl: 300 },
          { type: 'MX', value: 'mail.telemetry-grid.org', priority: 10 }
        ]
      });
      const evidId = 'ev-custody-02';
      const hash = computeSha256(dnsRawPayload);

      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, recorded_by
        ) VALUES (?, ?, 'https://dns.google/resolve?name=telemetry-grid.org', 'DNS_RECORD', 'Passive DNS Query', ?, ?, 'Observed', 'Analyst Vance')
      `).run(evidId, caseId, hash, dnsRawPayload);

      // Step 4: Log Audit Event for Evidence Ingestion
      db.prepare(`
        INSERT INTO audit_events (id, actor, action, entity_type, entity_id, details, status)
        VALUES ('aud-02', 'Analyst Vance', 'EVIDENCE_COMMITTED', 'EVIDENCE', ?, ?, 'SUCCESS')
      `).run(evidId, JSON.stringify({ sha256: hash, caseId }));

      // Step 5: Verify Chain of Custody
      const auditTrail = db.prepare('SELECT * FROM audit_events WHERE entity_id IN (?, ?) ORDER BY timestamp ASC').all(caseId, evidId) as any[];
      assertEqual(auditTrail.length, 2);
      assertEqual(auditTrail[0].action, 'CASE_CREATED');
      assertEqual(auditTrail[1].action, 'EVIDENCE_COMMITTED');
      assertIncludes(auditTrail[1].details, hash);

      db.close();
    }
  },

  // --------------------------------------------------------------------------
  // Pipeline 3: Case with Evidence -> Multi-Agent Run -> Citation Audit -> Export
  // --------------------------------------------------------------------------
  {
    name: 'T3_03_pipeline_agent_run_to_citation_verification_and_export',
    tier: 3,
    area: 'Pairwise Pipelines',
    fn: () => {
      const db = createInMemoryDatabase();

      // Step 1: Case and Evidence
      const caseId = 'case-agent-03';
      const evidId = 'EVID-1042';
      db.prepare("INSERT INTO cases (id, title, priority) VALUES (?, 'Agent Investigation', 'CRITICAL')").run(caseId);

      const rawEvidence = JSON.stringify({ ip: '195.140.228.17', asn: 'AS44123' });
      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status
        ) VALUES (?, ?, 'https://rdap.arin.net/ip/195.140.228.17', 'RDAP_REGISTRATION', 'RDAP IP Registration', 'hash1042', ?, 'Observed')
      `).run(evidId, caseId, rawEvidence);

      // Step 2: Multi-Agent State Machine Flow
      const sm = new AgentStateMachine();
      assertEqual(sm.currentState, 'PLANNED');

      // DHARMA starts RUNNING
      sm.transitionTo('RUNNING');
      const agentRunId = 'run-001';
      db.prepare(`
        INSERT INTO agent_runs (id, case_id, agent_name, status, input_parameters)
        VALUES (?, ?, 'DHARMA', 'RUNNING', ?)
      `).run(agentRunId, caseId, JSON.stringify({ goal: 'Correlate SCADA IP' }));

      // Synthesis with citation
      const findingsSummary = 'Target IP 195.140.228.17 is hosted in autonomous system AS44123 [EVID-1042].';

      // VERITAS verifies citations
      sm.transitionTo('VERIFYING');
      const validEvidenceSet = new Set(['EVID-1042']);
      const verificationResult = auditCitationsAgainstLedger(findingsSummary, validEvidenceSet);
      assertEqual(verificationResult.verified, true, 'Citation verification failed');

      // SCRIBE marks COMPLETED
      sm.transitionTo('COMPLETED');
      db.prepare(`
        UPDATE agent_runs
        SET status = 'COMPLETED', output_summary = ?, citations = ?
        WHERE id = ?
      `).run(findingsSummary, JSON.stringify(verificationResult.found), agentRunId);

      // Step 3: Multi-Format Report Export
      // STIX 2.1
      const stix = {
        type: 'bundle',
        id: 'bundle--test-agent-03',
        spec_version: '2.1',
        objects: [
          {
            type: 'report',
            id: 'report--03',
            name: 'Investigation Dossier - Agent Pipeline',
            description: findingsSummary
          }
        ]
      };
      validateStixBundle(stix);

      // HTML
      const html = `
        <!DOCTYPE html>
        <html>
        <head><style>body { background-color: #0A0D14; } @media print { body { color: #000; } }</style></head>
        <body>
          <h1>Executive Summary</h1>
          <p>${findingsSummary}</p>
          <h2>Evidence Ledger</h2>
        </body>
        </html>
      `;
      validateHtmlReport(html);

      // CSV
      const csv = 'evidence_id,case_id,source_url,content_hash\nEVID-1042,case-agent-03,https://rdap.arin.net,hash1042';
      validateCsvFormat(csv, ['evidence_id', 'content_hash']);

      db.close();
    }
  },

  // --------------------------------------------------------------------------
  // Pipeline 4: Terminal Command Execution -> Case Inspection -> System Telemetry
  // --------------------------------------------------------------------------
  {
    name: 'T3_04_pipeline_terminal_command_triaging_workflow',
    tier: 3,
    area: 'Pairwise Pipelines',
    fn: async () => {
      const db = createInMemoryDatabase();

      // Seed cases into database
      db.prepare("INSERT INTO cases (id, title, priority, status) VALUES ('CASE-101', 'Critical SCADA Outage', 'CRITICAL', 'ACTIVE')").run();
      db.prepare("INSERT INTO cases (id, title, priority, status) VALUES ('CASE-102', 'Ransomware Spill', 'HIGH', 'OPEN')").run();

      // Step 1: Execute `cases list` via terminal
      const listRes = await evaluateTerminalCommand('cases list', db);
      assertEqual(listRes.success, true);
      assertIncludes(listRes.output, 'CASE-101');
      assertIncludes(listRes.output, 'CASE-102');

      // Step 2: Execute `case show CASE-101`
      const showRes = await evaluateTerminalCommand('case show CASE-101', db);
      assertEqual(showRes.success, true);
      assertIncludes(showRes.output, 'Critical SCADA Outage');
      assertIncludes(showRes.output, 'CRITICAL');

      // Step 3: Execute `system health`
      const healthRes = await evaluateTerminalCommand('system health', db);
      assertEqual(healthRes.success, true);
      assertIncludes(healthRes.output, 'SYSTEM HEALTH TELEMETRY');
      assertIncludes(healthRes.output, 'Database: ONLINE');

      db.close();
    }
  },

  // --------------------------------------------------------------------------
  // Pipeline 5: Watchlist Trigger -> Feed Ingestion Match -> Alert & Audit
  // --------------------------------------------------------------------------
  {
    name: 'T3_05_pipeline_watchlist_feed_match_and_audit',
    tier: 3,
    area: 'Pairwise Pipelines',
    fn: () => {
      const db = createInMemoryDatabase();

      // Step 1: Create Watchlist Rule for CVE pattern
      const watchlistId = 'watch-01';
      db.prepare(`
        INSERT INTO watchlists (id, name, target_type, pattern, alert_severity)
        VALUES (?, 'Modbus Exploit Monitor', 'CVE', 'CVE-2026-1189', 'CRITICAL')
      `).run(watchlistId);

      // Step 2: Ingest CTI Feed Record matching pattern
      const feedRecordId = 'feed-item-99';
      const cvePayload = JSON.stringify({ cve: 'CVE-2026-1189', description: 'SCADA Modbus overflow' });
      db.prepare(`
        INSERT INTO feed_records (
          id, feed_name, title, category, severity, source_url, published_at, payload
        ) VALUES (?, 'CISA_KEV', 'SCADA Vulnerability', 'VULNERABILITY', 'CRITICAL', 'https://cisa.gov/kev', '2026-10-28', ?)
      `).run(feedRecordId, cvePayload);

      // Step 3: Watchlist Evaluator Match Logic
      const watch = db.prepare('SELECT * FROM watchlists WHERE id = ?').get(watchlistId) as any;
      const feed = db.prepare('SELECT * FROM feed_records WHERE id = ?').get(feedRecordId) as any;

      if (feed.payload.includes(watch.pattern)) {
        // Increment match count
        db.prepare(`
          UPDATE watchlists
          SET match_count = match_count + 1, last_matched_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
          WHERE id = ?
        `).run(watchlistId);

        // Record Audit Event
        db.prepare(`
          INSERT INTO audit_events (id, actor, action, entity_type, entity_id, details, status)
          VALUES ('aud-match-1', 'WATCHLIST_ENGINE', 'WATCHLIST_ALERT_TRIGGERED', 'WATCHLIST', ?, ?, 'WARNING')
        `).run(watchlistId, JSON.stringify({ matchedFeedId: feedRecordId, pattern: watch.pattern }));
      }

      // Step 4: Verify Watchlist updated and Audit Event recorded
      const updatedWatch = db.prepare('SELECT match_count, last_matched_at FROM watchlists WHERE id = ?').get(watchlistId) as any;
      assertEqual(updatedWatch.match_count, 1);
      assert(updatedWatch.last_matched_at !== null);

      const auditRow = db.prepare('SELECT * FROM audit_events WHERE action = ?').get('WATCHLIST_ALERT_TRIGGERED') as any;
      assert(auditRow !== undefined);
      assertIncludes(auditRow.details, 'CVE-2026-1189');

      db.close();
    }
  }
];
