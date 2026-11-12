# EYE OF DHARMA (EOD) — Test Infrastructure & Verification Architecture

## 1. Test Philosophy & Principles

The testing framework for EYE OF DHARMA is engineered around four core tenets:

1. **Opaque-Box & Requirement-Driven**:
   Tests treat the platform as a sovereign black-box system. All test assertions are derived strictly from requirements in `ORIGINAL_REQUEST.md`, authoritative protocol standards (RFC 7946 GeoJSON, RFC 7483 RDAP, RFC 6962 Certificate Transparency, RFC 4180 CSV, STIX 2.1), and mathematical invariants (SHA-256 digests, CIDR subnet math, Token Bucket differential equations). No test relies on private variable state or internal mock shortcuts.

2. **Test Integrity (Zero Facades)**:
   Every test executes real logic against real outputs. Facade tests that assert `true === true` or mock out the code under test to always succeed are strictly prohibited. Tests verify actual database constraints, real trigger abortions, genuine network parser behaviors, and real crypto hashing.

3. **Progressive Testability & Isolation**:
   Every test suite is fully self-contained. It prepares its own state, executes isolated transactions or network requests, and cleans up deterministically. Tests can run against a live running backend HTTP server or via in-process protocol drivers during isolated milestone validation.

4. **Adversarial & Edge-Condition Rigor**:
   In addition to standard happy-path workflows, the suite subjects the platform to adversarial boundary conditions: IPv6-mapped IPv4 loopback SSRF bypasses, octal/hex IP obfuscation, DNS rebinding TOCTOU windows, SQLite trigger bypass attempts, shell injection metacharacters, and oversized multi-megabyte payloads.

---

## 2. Test Execution & CLI Commands

The test runner is located at `tests/runner.ts` and can be executed directly using Node.js and TypeScript via `tsx`:

### Full E2E Test Suite Execution
```bash
# Run all test tiers (Tier 1 through Tier 4) with summary dashboard
npx tsx tests/runner.ts
```

### Running Specific Tiers
```bash
# Tier 1: Feature Coverage (Core Functional Isolation)
npx tsx tests/runner.ts --tier 1

# Tier 2: Boundary & Corner Cases (Adversarial, Encodings, Limits)
npx tsx tests/runner.ts --tier 2

# Tier 3: Cross-Feature Combinations (Pairwise End-to-End Flows)
npx tsx tests/runner.ts --tier 3

# Tier 4: Real-World Scenarios (Dossiers, APTs, Hazard Triage)
npx tsx tests/runner.ts --tier 4
```

### Advanced Flags
- `--bail`: Stop execution immediately upon first failure.
- `--verbose`: Print detailed logs for every test step.
- `--json`: Output machine-readable test execution report.
- `--port <number>`: Target running server port (defaults to `3000` or `process.env.PORT`).

---

## 3. Four-Tier Test Architecture

```
+-------------------------------------------------------------------------------+
|                       EYE OF DHARMA TEST SUITE HIERARCHY                      |
+-------------------------------------------------------------------------------+
|  TIER 4: REAL-WORLD APPLICATION SCENARIOS                                     |
|  - Operation Arctic Phoenix (APT-44, SCADA, Certificate Transparency, Dossier)|
|  - Ransomware Nexus 2026 (CISA KEV, Ransomware Actors, Host Mapping, Report)  |
|  - Real-Time Hazard Triage (USGS Seismic, NASA EONET, Spatial Correlation)    |
+-------------------------------------------------------------------------------+
|  TIER 3: CROSS-FEATURE PAIRWISE COMBINATIONS                                  |
|  - Ingestion -> Evidence Ledger -> Entity Graph -> Case Linkage               |
|  - Case Creation -> Passive Footprint -> Provenance -> Custody Audit          |
|  - Case -> Multi-Agent Run -> Citation Audit -> Multi-Format Report Export    |
|  - Terminal Console -> Case Triage -> Evidence Lookup -> System Telemetry     |
|  - Watchlist Hit -> Live Feed Match -> Alert -> Audit Log                     |
+-------------------------------------------------------------------------------+
|  TIER 2: BOUNDARY, CORNER & ADVERSARIAL CASES                                 |
|  - Engine trigger updates/deletes rejection (EVIDENCE_IMMUTABILITY_VIOLATION) |
|  - SSRF Bypasses: [::ffff:127.0.0.1], 017700000001, 169.254.169.254, gopher://|
|  - Oversized payloads (>5MB cap), 5000ms socket timeouts, DNS failures        |
|  - Terminal shell injection (; && | ` $() > <), buffer limits (>256 chars)    |
|  - Footprint negative results (200 OK) vs upstream network failures (504)    |
|  - Multi-agent invalid state jumps, ungrounded citations, prompt injection    |
+-------------------------------------------------------------------------------+
|  TIER 1: FEATURE ISOLATION COVERAGE (>=5 tests per feature area)              |
|  - Area 1: Relational Schema, DDL, Immutability Triggers (5+ tests)           |
|  - Area 2: 6-Stage SSRF Firewall & Zod Input Validation (5+ tests)            |
|  - Area 3: OSINT/CTI Connectors (USGS, EONET, CISA, crt.sh, DNS/RDAP, RSS)   |
|  - Area 4: Operations Center UI Contracts, Nav Rail, Console (5+ tests)       |
|  - Area 5: Digital Footprint Passive Recon, Negative vs Failure (5+ tests)    |
|  - Area 6: Multi-Agent Engine, Anti-Hallucination Citations, Dossiers         |
+-------------------------------------------------------------------------------+
```

---

## 4. Feature Inventory & Tier Mapping

| # | Feature | Scope / Subsystem | Milestone | Primary Test Tier | Test Suite File |
|---|---------|-------------------|-----------|-------------------|-----------------|
| 1 | Relational Schema DDL (9 Tables) | Database Storage | M1 | Tier 1 (Area 1) | `tests/e2e/tier1_feature.test.ts` |
| 2 | Evidence Ledger Immutability Triggers | Storage Security | M1 | Tier 1 (Area 1), Tier 2 (Area 1) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 3 | 6-Stage SSRF Firewall | Network Security | M1 | Tier 1 (Area 2), Tier 2 (Area 2) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 4 | Zod Schema Validation | Application Security | M1 | Tier 1 (Area 2), Tier 2 (Area 2) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 5 | Parameterized Queries & Repositories | Database Security | M1 | Tier 1 (Area 1), Tier 2 (Area 1) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 6 | Session & Double-Submit CSRF Security | Web Security | M1 | Tier 1 (Area 2) | `tests/e2e/tier1_feature.test.ts` |
| 7 | Deterministic Synthetic Seed Data | Storage / Seed | M1 | Tier 1 (Area 1), Tier 4 | `tests/e2e/tier1_feature.test.ts`, `tier4_scenarios.test.ts` |
| 8 | REST API Endpoints (Core 29 routes) | Web Services | M1 | Tier 1 (All Areas) | `tests/e2e/tier1_feature.test.ts` |
| 9 | Audit Event Logging | Audit & Security | M1 | Tier 1 (Area 1), Tier 3 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts` |
| 10 | Backend Health & Telemetry | System Health | M1 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 11 | Connector Base Architecture (`IConnector`) | OSINT Framework | M2 | Tier 1 (Area 3) | `tests/e2e/tier1_feature.test.ts` |
| 12 | Token Bucket Rate Limiting | OSINT Reliability | M2 | Tier 1 (Area 3), Tier 2 (Area 3) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 13 | Exponential Backoff with Full Jitter | OSINT Reliability | M2 | Tier 1 (Area 3), Tier 2 (Area 3) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 14 | Circuit Breaker & Health Metrics | OSINT Reliability | M2 | Tier 1 (Area 3), Tier 2 (Area 3) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 15 | Deduplication & SHA-256 Hashing | Data Provenance | M2 | Tier 1 (Area 1, Area 3), Tier 3 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts` |
| 16 | 6-State Source Attribution | Intelligence Provenance | M2 | Tier 1 (Area 3) | `tests/e2e/tier1_feature.test.ts` |
| 17 | USGS Earthquakes GeoJSON Connector | OSINT Connector | M2 | Tier 1 (Area 3), Tier 4 (Scenario 3) | `tests/e2e/tier1_feature.test.ts`, `tier4_scenarios.test.ts` |
| 18 | NASA EONET v3 Hazards Connector | OSINT Connector | M2 | Tier 1 (Area 3), Tier 4 (Scenario 3) | `tests/e2e/tier1_feature.test.ts`, `tier4_scenarios.test.ts` |
| 19 | CISA KEV Catalog Connector | CTI Connector | M2 | Tier 1 (Area 3), Tier 4 (Scenario 2) | `tests/e2e/tier1_feature.test.ts`, `tier4_scenarios.test.ts` |
| 20 | CISA Advisories RSS Connector | CTI Connector | M2 | Tier 1 (Area 3) | `tests/e2e/tier1_feature.test.ts` |
| 21 | crt.sh Certificate Search Connector | OSINT Connector | M2 | Tier 1 (Area 3), Tier 4 (Scenario 1) | `tests/e2e/tier1_feature.test.ts`, `tier4_scenarios.test.ts` |
| 22 | DNS Resolution & RDAP Connector | Network Connector | M2 | Tier 1 (Area 3, Area 5) | `tests/e2e/tier1_feature.test.ts` |
| 23 | Public RSS/Atom Feeds Connector | OSINT Connector | M2 | Tier 1 (Area 3), Tier 2 (Area 3) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 24 | Operations Center Dark Theme Contract | UI Architecture | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 25 | 15 Navigation Rail Module Routes | UI Architecture | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 26 | MapLibre GL Geospatial Map Contract | Geospatial UI | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 27 | Toggleable Intelligence Map Layers | Geospatial UI | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 28 | Supercluster Map Point Clustering | Geospatial UI | M3 | Tier 2 (Area 4) | `tests/e2e/tier2_boundary.test.ts` |
| 29 | 15 RPM Radar Sweep Animation Contract | UI Visual FX | M3 | Tier 1 (Area 4), Tier 2 (Area 4) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 30 | Live Intelligence Event Ticker Contract | UI Streaming | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 31 | Cytoscape.js Entity Graph (3 Edge Styles)| Visual Graph | M3 | Tier 1 (Area 4), Tier 3 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts` |
| 32 | Chronological Investigation Timeline | UI Timeline | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 33 | Functional Ctrl+K Command Palette | Command & Control | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 34 | Allowlisted Terminal Console | Command & Control | M3 | Tier 1 (Area 4), Tier 2 (Area 4) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 35 | Accessibility & Reduced-Motion Rules | Frontend A11y | M3 | Tier 1 (Area 4), Tier 2 (Area 4) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 36 | Responsive Desktop/Tablet/Mobile Layout | Frontend Shell | M3 | Tier 1 (Area 4) | `tests/e2e/tier1_feature.test.ts` |
| 37 | Digital Footprint Query Engine | Reconnaissance | M4 | Tier 1 (Area 5) | `tests/e2e/tier1_feature.test.ts` |
| 38 | Upfront Query Confirmation Modal | Safeguards | M4 | Tier 1 (Area 5), Tier 2 (Area 5) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 39 | Passive-Only Indicator & Enforcement | Safeguards | M4 | Tier 1 (Area 5) | `tests/e2e/tier1_feature.test.ts` |
| 40 | Negative Result vs Failure Distinction | Reconnaissance | M4 | Tier 1 (Area 5), Tier 2 (Area 5) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 41 | Case Management Workspace (6 Tabs) | Case Management | M4 | Tier 1 (Area 5), Tier 3 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts` |
| 42 | Evidence Attachment & Linking | Case Management | M4 | Tier 1 (Area 1, Area 5), Tier 3 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts` |
| 43 | Entity Tagging & Relationship Graph | Graph Analytics | M4 | Tier 1 (Area 1), Tier 3 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts` |
| 44 | Chain of Custody Preservation | Legal Provenance | M4 | Tier 1 (Area 1), Tier 3 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts` |
| 45 | Multi-Agent Orchestration (7 Roles) | AI Subsystem | M5 | Tier 1 (Area 6) | `tests/e2e/tier1_feature.test.ts` |
| 46 | Bounded State Machine (5 States) | AI Subsystem | M5 | Tier 1 (Area 6), Tier 2 (Area 6) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 47 | Tool Permission Sandboxing | AI Security | M5 | Tier 1 (Area 6), Tier 2 (Area 6) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 48 | Anti-Hallucination Citation Engine | Grounding | M5 | Tier 1 (Area 6), Tier 2 (Area 6) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 49 | Indirect Prompt Injection Guards | LLM Security | M5 | Tier 1 (Area 6), Tier 2 (Area 6) | `tests/e2e/tier1_feature.test.ts`, `tier2_boundary.test.ts` |
| 50 | Contradiction Flagging Engine | Verification | M5 | Tier 1 (Area 6) | `tests/e2e/tier1_feature.test.ts` |
| 51 | 100% Deterministic No-AI Fallback | Fallback | M5 | Tier 1 (Area 6), Tier 3, Tier 4 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts`, `tier4_scenarios.test.ts` |
| 52 | Multi-Provider LLM Abstraction | AI Infrastructure | M5 | Tier 1 (Area 6) | `tests/e2e/tier1_feature.test.ts` |
| 53 | 8-Section Investigation Dossier | Reporting | M5 | Tier 1 (Area 6), Tier 4 | `tests/e2e/tier1_feature.test.ts`, `tier4_scenarios.test.ts` |
| 54 | Multi-Format Export Engine (HTML/PDF/JSON/CSV) | Reporting | M5 | Tier 1 (Area 6), Tier 3, Tier 4 | `tests/e2e/tier1_feature.test.ts`, `tier3_pairwise.test.ts`, `tier4_scenarios.test.ts` |
| 55 | Opaque-Box E2E Test Suite | Test Infrastructure| M6 | All Tiers (1-4) | `tests/runner.ts`, `tests/e2e/**` |
| 56 | Adversarial Coverage Hardening | Test Quality | M6 | Tier 2 (Boundary) | `tests/e2e/tier2_boundary.test.ts` |
| 57 | Forensic Integrity Audit | Quality Assurance | M6 | Tier 1-4 Verification | `TEST_READY.md` |

---

## 5. Test Directory Structure

```
tests/
├── e2e/
│   ├── helpers.ts                # Shared HTTP client, DB fixture setup, crypto assertions
│   ├── tier1_feature.test.ts     # Tier 1: 36 feature isolation tests (6 areas x 6 tests)
│   ├── tier2_boundary.test.ts    # Tier 2: 36 boundary & corner cases (6 areas x 6 tests)
│   ├── tier3_pairwise.test.ts    # Tier 3: 5 end-to-end multi-feature data pipelines
│   └── tier4_scenarios.test.ts   # Tier 4: 3 realistic investigation mission scenarios
└── runner.ts                     # Standalone CLI test runner and reporter
```
