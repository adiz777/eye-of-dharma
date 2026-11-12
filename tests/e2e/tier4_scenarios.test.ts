/**
 * EYE OF DHARMA (EOD) — E2E Test Suite: Tier 4 (Real-World Application Scenarios)
 * Realistic end-to-end digital investigations modeling operational scenarios.
 */

import {
  TestCase,
  assert,
  assertEqual,
  assertIncludes,
  computeSha256,
  createInMemoryDatabase,
  validateStixBundle,
  validateCsvFormat,
  validateHtmlReport
} from './helpers.js';

export const tier4Tests: TestCase[] = [
  // --------------------------------------------------------------------------
  // Scenario 1: "Operation Arctic Phoenix"
  // APT-44 targeting Nordic renewable energy SCADA infrastructure
  // --------------------------------------------------------------------------
  {
    name: 'T4_01_scenario_operation_arctic_phoenix',
    tier: 4,
    area: 'Mission Scenarios',
    fn: () => {
      const db = createInMemoryDatabase();

      // Step 1: Initialize Case for Operation Arctic Phoenix
      const caseId = 'case-arctic-phoenix-001';
      db.prepare(`
        INSERT INTO cases (
          id, title, description, status, priority, lead_analyst, tags, summary, is_synthetic
        ) VALUES (
          ?, 'Operation Arctic Phoenix - Grid Infiltration',
          'Suspected APT-44 campaign targeting European and Nordic renewable energy SCADA telemetry infrastructure.',
          'ACTIVE', 'CRITICAL', 'Senior Agent Vance', '["APT-44", "SCADA", "ENERGY", "ZERO-DAY"]',
          'Target domain resolves to malicious C2 infrastructure exploiting Modbus vulnerabilities.', 1
        )
      `).run(caseId);

      // Step 2: Ingest CISA ICS Advisory into Evidence Ledger
      const cisaAdvisory = JSON.stringify({
        advisoryId: 'ICSA-2026-1189',
        title: 'Modbus Protocol Vulnerability in Energy SCADA Telemetry',
        vendor: 'Nordic-Power-Systems',
        cve: 'CVE-2026-1189',
        cvss: 9.8,
        description: 'Improper boundary check allows unauthorized remote setpoint alteration.'
      });
      const evidCisaId = 'ev-arctic-cisa-01';
      const cisaHash = computeSha256(cisaAdvisory);

      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score, is_synthetic
        ) VALUES (?, ?, 'https://www.cisa.gov/news-events/ics-advisories/icsa-2026-1189', 'CISA_ADVISORY', 'CISA ICS Advisory ICSA-2026-1189', ?, ?, 'Source-reported', 0.98, 1)
      `).run(evidCisaId, caseId, cisaHash, cisaAdvisory);

      // Step 3: Certificate Transparency Footprint (crt.sh)
      const crtPayload = JSON.stringify({
        commonName: 'scada-telemetry-portal.nordic-power.net',
        sans: ['scada-telemetry-portal.nordic-power.net', 'vpn.nordic-power.net'],
        issuer: 'CN=Let\'s Encrypt Authority X3',
        serial: '04a9b8c7d6e5'
      });
      const evidCrtId = 'ev-arctic-crt-02';
      const crtHash = computeSha256(crtPayload);

      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score, is_synthetic
        ) VALUES (?, ?, 'https://crt.sh/?q=nordic-power.net&output=json', 'CRT_SH', 'Certificate Search nordic-power.net', ?, ?, 'Observed', 1.0, 1)
      `).run(evidCrtId, caseId, crtHash, crtPayload);

      // Step 4: Map Threat Entities
      const entActor = 'ent-ap-actor';
      const entDomain = 'ent-ap-domain';
      const entIp = 'ent-ap-ip';
      const entVuln = 'ent-ap-vuln';

      db.prepare("INSERT INTO entities (id, case_id, name, type, value, risk_score, is_synthetic) VALUES (?, ?, 'APT-44 (Arctic Phoenix)', 'ACTOR', 'APT-44', 95, 1)").run(entActor, caseId);
      db.prepare("INSERT INTO entities (id, case_id, name, type, value, risk_score, is_synthetic) VALUES (?, ?, 'scada-telemetry-portal.nordic-power.net', 'DOMAIN', 'scada-telemetry-portal.nordic-power.net', 88, 1)").run(entDomain, caseId);
      db.prepare("INSERT INTO entities (id, case_id, name, type, value, risk_score, is_synthetic) VALUES (?, ?, '195.140.228.17', 'IP_ADDRESS', '195.140.228.17', 90, 1)").run(entIp, caseId);
      db.prepare("INSERT INTO entities (id, case_id, name, type, value, risk_score, is_synthetic) VALUES (?, ?, 'CVE-2026-1189', 'VULNERABILITY', 'CVE-2026-1189', 98, 1)").run(entVuln, caseId);

      // Step 5: Establish Verified & Inferred Graph Relationships
      db.prepare(`
        INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, evidence_id, status, is_synthetic)
        VALUES ('rel-ap-1', ?, ?, 'ATTRIBUTED_TO', 0.92, ?, 'VERIFIED', 1)
      `).run(entActor, entDomain, evidCrtId);

      db.prepare(`
        INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, status, is_synthetic)
        VALUES ('rel-ap-2', ?, ?, 'RESOLVES_TO', 0.99, 'VERIFIED', 1)
      `).run(entDomain, entIp);

      db.prepare(`
        INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, evidence_id, status, is_synthetic)
        VALUES ('rel-ap-3', ?, ?, 'EXPLOITS', 0.85, ?, 'INFERRED', 1)
      `).run(entActor, entVuln, evidCisaId);

      // Step 6: Create Threat Indicators
      db.prepare(`
        INSERT INTO threat_indicators (
          id, indicator_type, indicator_value, threat_actor, campaign, severity, confidence, source, is_synthetic
        ) VALUES (
          'ti-ap-01', 'DOMAIN', 'scada-telemetry-portal.nordic-power.net', 'APT-44', 'Arctic Phoenix', 'CRITICAL', 0.95, 'OSINT CT Logs', 1
        )
      `).run();

      db.prepare(`
        INSERT INTO threat_indicators (
          id, indicator_type, indicator_value, threat_actor, campaign, severity, confidence, source, is_synthetic
        ) VALUES (
          'ti-ap-02', 'IPV4', '195.140.228.17', 'APT-44', 'Arctic Phoenix', 'CRITICAL', 0.90, 'Passive DNS Lookup', 1
        )
      `).run();

      // Step 7: Dossier Synthesis & Multi-Format Validation
      const stixBundle = {
        type: 'bundle',
        id: 'bundle--arctic-phoenix-dossier',
        spec_version: '2.1',
        objects: [
          {
            type: 'report',
            id: 'report--arctic-01',
            name: 'Investigation Dossier: Operation Arctic Phoenix',
            published: '2026-10-28T16:00:00Z'
          },
          {
            type: 'threat-actor',
            id: 'threat-actor--apt44',
            name: 'APT-44 (Arctic Phoenix)'
          },
          {
            type: 'domain-name',
            id: 'domain-name--scada-portal',
            value: 'scada-telemetry-portal.nordic-power.net'
          }
        ]
      };
      validateStixBundle(stixBundle);

      const htmlReport = `
        <!DOCTYPE html>
        <html>
        <head><style>body { background-color: #0A0D14; } @media print { body { color: #000; } }</style></head>
        <body>
          <h1>Executive Summary</h1>
          <p>Operation Arctic Phoenix: Investigation into APT-44 C2 operations targeting SCADA grid controllers.</p>
          <h2>Evidence Ledger</h2>
          <p>Evidence ID: ${evidCisaId} | Hash: ${cisaHash}</p>
        </body>
        </html>
      `;
      validateHtmlReport(htmlReport);

      // Verify Database Integrity
      const evidenceCount = db.prepare('SELECT count(*) as count FROM evidence_ledger WHERE case_id = ?').get(caseId) as any;
      assertEqual(evidenceCount.count, 2);

      const entityCount = db.prepare('SELECT count(*) as count FROM entities WHERE case_id = ?').get(caseId) as any;
      assertEqual(entityCount.count, 4);

      db.close();
    }
  },

  // --------------------------------------------------------------------------
  // Scenario 2: "Ransomware Nexus 2026"
  // Darknet extortion syndicate correlated with CISA KEV and victim mapping
  // --------------------------------------------------------------------------
  {
    name: 'T4_02_scenario_ransomware_nexus_2026',
    tier: 4,
    area: 'Mission Scenarios',
    fn: () => {
      const db = createInMemoryDatabase();

      // Step 1: Open Case for Ransomware Nexus
      const caseId = 'case-nexus-002';
      db.prepare(`
        INSERT INTO cases (
          id, title, description, status, priority, tags, is_synthetic
        ) VALUES (
          ?, 'Ransomware Nexus 2026 Syndicate',
          'Investigation into double-extortion darknet operations leaking enterprise telemetry.',
          'OPEN', 'HIGH', '["RANSOMWARE", "TOR", "EXFILTRATION"]', 1
        )
      `).run(caseId);

      // Step 2: Ingest CISA KEV Exploited Vulnerability
      const kevRecord = JSON.stringify({
        cveID: 'CVE-2026-48356',
        vendorProject: 'Adobe',
        product: 'Commerce',
        vulnerabilityName: 'Commerce Unrestricted Upload Leading to Remote Code Execution',
        dateAdded: '2026-10-27',
        knownRansomwareCampaignUse: 'Known',
        dueDate: '2026-11-10'
      });
      const evidKevId = 'ev-nexus-kev-01';
      const kevHash = computeSha256(kevRecord);

      db.prepare(`
        INSERT INTO evidence_ledger (
          id, case_id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score, is_synthetic
        ) VALUES (?, ?, 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'CISA_KEV', 'CISA KEV CVE-2026-48356', ?, ?, 'Source-reported', 1.0, 1)
      `).run(evidKevId, caseId, kevHash, kevRecord);

      // Step 3: Entities for Syndicate
      const entGroup = 'ent-nexus-group';
      const entCve = 'ent-nexus-cve';
      const entTorExit = 'ent-nexus-tor';

      db.prepare("INSERT INTO entities (id, case_id, name, type, value, risk_score, is_synthetic) VALUES (?, ?, 'Nexus Locker Group', 'ACTOR', 'Nexus Locker', 85, 1)").run(entGroup, caseId);
      db.prepare("INSERT INTO entities (id, case_id, name, type, value, risk_score, is_synthetic) VALUES (?, ?, 'CVE-2026-48356', 'VULNERABILITY', 'CVE-2026-48356', 92, 1)").run(entCve, caseId);
      db.prepare("INSERT INTO entities (id, case_id, name, type, value, risk_score, is_synthetic) VALUES (?, ?, '185.220.101.5', 'IP_ADDRESS', '185.220.101.5', 65, 1)").run(entTorExit, caseId);

      // Step 4: Relationships
      db.prepare(`
        INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, evidence_id, status, is_synthetic)
        VALUES ('rel-nexus-1', ?, ?, 'EXPLOITS', 0.95, ?, 'VERIFIED', 1)
      `).run(entGroup, entCve, evidKevId);

      db.prepare(`
        INSERT INTO relationships (id, source_entity_id, target_entity_id, relation_type, confidence, status, is_synthetic)
        VALUES ('rel-nexus-2', ?, ?, 'COMMUNICATES_WITH', 0.70, 'INFERRED', 1)
      `).run(entGroup, entTorExit);

      // Step 5: Export CSV Evidence & Indicators
      const csvEvidence = `evidence_id,case_id,source_url,content_hash,verification_status\n${evidKevId},${caseId},https://cisa.gov,${kevHash},Source-reported`;
      validateCsvFormat(csvEvidence, ['evidence_id', 'case_id', 'content_hash']);

      // Verification of case and relationships
      const caseRow = db.prepare('SELECT title, priority FROM cases WHERE id = ?').get(caseId) as any;
      assertEqual(caseRow.priority, 'HIGH');
      assertEqual(caseRow.title, 'Ransomware Nexus 2026 Syndicate');

      db.close();
    }
  },

  // --------------------------------------------------------------------------
  // Scenario 3: Real-Time Public Intelligence Event Triage
  // USGS Earthquake & NASA EONET Hazard Correlation
  // --------------------------------------------------------------------------
  {
    name: 'T3_03_scenario_public_intelligence_hazard_triage',
    tier: 4,
    area: 'Mission Scenarios',
    fn: () => {
      const db = createInMemoryDatabase();

      // Step 1: Ingest USGS Earthquake Record into Feed Cache
      const usgsEventId = 'us7000ridge';
      const usgsPayload = JSON.stringify({
        id: usgsEventId,
        mag: 6.7,
        place: 'central Mid-Atlantic Ridge',
        time: '2026-10-28T14:30:00Z',
        coordinates: [-19.8598, 0.1685, 10.0]
      });

      db.prepare(`
        INSERT INTO feed_records (
          id, feed_name, external_id, title, category, severity,
          source_url, published_at, payload, geocoding_lat, geocoding_lon
        ) VALUES (
          'feed-usgs-01', 'USGS', ?, 'M 6.7 - central Mid-Atlantic Ridge', 'EARTHQUAKE', 'HIGH',
          'https://earthquake.usgs.gov/earthquakes/eventpage/us7000ridge', '2026-10-28T14:30:00Z',
          ?, 0.1685, -19.8598
        )
      `).run(usgsEventId, usgsPayload);

      // Step 2: Ingest NASA EONET Storm Event
      const eonetEventId = 'EONET_3342';
      const eonetPayload = JSON.stringify({
        id: eonetEventId,
        title: 'Tropical Storm Epsilon',
        category: 'severeStorms',
        coordinates: [-22.5, 4.2]
      });

      db.prepare(`
        INSERT INTO feed_records (
          id, feed_name, external_id, title, category, severity,
          source_url, published_at, payload, geocoding_lat, geocoding_lon
        ) VALUES (
          'feed-eonet-01', 'NASA_EONET', ?, 'Tropical Storm Epsilon', 'HAZARD', 'MEDIUM',
          'https://eonet.gsfc.nasa.gov/api/v3/events/EONET_3342', '2026-10-28T12:00:00Z',
          ?, 4.2, -22.5
        )
      `).run(eonetEventId, eonetPayload);

      // Step 3: Spatial Proximity & Hazard Query (Bounding Box search)
      // Query events in Atlantic region: lat between -5 and 10, lon between -30 and -10
      const regionalEvents = db.prepare(`
        SELECT feed_name, title, category, severity, geocoding_lat, geocoding_lon
        FROM feed_records
        WHERE geocoding_lat BETWEEN -5.0 AND 10.0
          AND geocoding_lon BETWEEN -30.0 AND -10.0
      `).all() as any[];

      assertEqual(regionalEvents.length, 2, 'Spatial bounding-box query should return both hazard events');
      assert(regionalEvents.some(e => e.feed_name === 'USGS'));
      assert(regionalEvents.some(e => e.feed_name === 'NASA_EONET'));

      // Step 4: Promote high-severity hazard to Evidence Ledger
      const usgsRow = regionalEvents.find(e => e.feed_name === 'USGS');
      const hash = computeSha256(usgsPayload);

      db.prepare(`
        INSERT INTO evidence_ledger (
          id, source_url, source_type, source_title,
          content_fingerprint, raw_content, verification_status, confidence_score
        ) VALUES (
          'ev-hazard-01', 'https://earthquake.usgs.gov/earthquakes/eventpage/us7000ridge',
          'USGS_EARTHQUAKE', ?, ?, ?, 'Observed', 1.0
        )
      `).run(usgsRow.title, hash, usgsPayload);

      const promotedEvidence = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get('ev-hazard-01') as any;
      assertEqual(promotedEvidence.source_type, 'USGS_EARTHQUAKE');
      assertEqual(promotedEvidence.content_fingerprint, hash);

      db.close();
    }
  }
];
