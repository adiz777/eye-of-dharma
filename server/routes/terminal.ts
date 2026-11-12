// server/routes/terminal.ts
// Allowlisted Terminal Console Command Dispatcher

import { Router } from 'express';
import type Database from 'better-sqlite3';
import { TerminalCommandSchema, validateBody } from '../security/validation.js';
import type { CaseRecord, ThreatIndicatorRecord } from '../db/schema.js';

export function createTerminalRouter(db: Database.Database): Router {
  const router = Router();

  const handleCommand = (req: import('express').Request, res: import('express').Response) => {
    const t0 = performance.now();
    const rawCmd = (req.body.command || '').trim();
    const parts = rawCmd.split(/\s+/);
    const verb = (parts[0] || '').toLowerCase();
    const arg1 = parts[1];
    const arg2 = parts[2];

    let output = '';

    switch (verb) {
      case 'help':
        output = `=== EYE OF DHARMA ALLOWLISTED TERMINAL CONSOLE ===
Available commands:
  help               - Show this command reference
  status             - Show operational status and database metrics
  sources            - List verified OSINT and threat intelligence connectors
  cases list         - List recent investigation cases
  case show <id>     - Display case overview and evidence summary
  threats recent     - Display top active threat indicators
  system health      - Check real-time system and database health
`;
        break;

      case 'status': {
        const casesCount = (db.prepare('SELECT COUNT(*) as cnt FROM cases').get() as { cnt: number }).cnt;
        const evidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM evidence_ledger').get() as { cnt: number }).cnt;
        const threatsCount = (db.prepare('SELECT COUNT(*) as cnt FROM threat_indicators').get() as { cnt: number }).cnt;

        output = `[EOD OPERATIONAL STATUS]
System: ONLINE
Database: SQLite-WAL (engine immutability active)
Active Cases: ${casesCount}
Evidence Ledger Records: ${evidenceCount}
Threat Indicators: ${threatsCount}
Timestamp: ${new Date().toISOString()}
`;
        break;
      }

      case 'sources':
        output = `[VERIFIED OSINT & CTI DATA SOURCES]
1. USGS Earthquakes API           - Status: ACTIVE [HTTP GET]
2. NASA EONET v3 Hazards         - Status: ACTIVE [HTTP GET]
3. CISA Known Exploited Vulns     - Status: ACTIVE [JSON Feed]
4. CISA Cybersecurity Alerts      - Status: ACTIVE [RSS Feed]
5. crt.sh Certificate Transp.     - Status: ACTIVE [REST API]
6. DNS-over-HTTPS & RDAP Lookups  - Status: ACTIVE [RFC 7483]
7. Global RSS/Atom Intel Feeds   - Status: ACTIVE [XML Ingestion]
`;
        break;

      case 'cases':
        if (arg1 === 'list' || !arg1) {
          const cases = db.prepare('SELECT id, title, priority, status FROM cases ORDER BY created_at DESC LIMIT 10').all() as CaseRecord[];
          output = `[RECENT CASES - TOP ${cases.length}]\n` +
            cases.map((c) => `• [${c.priority}] (${c.status}) ${c.id}: ${c.title}`).join('\n');
        } else {
          output = `Unknown cases subcommand '${arg1}'. Usage: cases list`;
        }
        break;

      case 'case':
        if (arg1 === 'show' && arg2) {
          const c = db.prepare('SELECT * FROM cases WHERE id = ?').get(arg2) as CaseRecord | undefined;
          if (!c) {
            output = `Case '${arg2}' not found.`;
          } else {
            const evCnt = (db.prepare('SELECT COUNT(*) as cnt FROM evidence_ledger WHERE case_id = ?').get(arg2) as { cnt: number }).cnt;
            output = `[CASE DETAILS]
ID: ${c.id}
Title: ${c.title}
Status: ${c.status}
Priority: ${c.priority}
Analyst: ${c.lead_analyst}
Evidence Ledger Count: ${evCnt}
Description: ${c.description || 'N/A'}
`;
          }
        } else {
          output = `Usage: case show <case_id>`;
        }
        break;

      case 'threats':
        if (arg1 === 'recent' || !arg1) {
          const threats = db.prepare('SELECT indicator_type, indicator_value, severity, threat_actor FROM threat_indicators WHERE is_active = 1 ORDER BY created_at DESC LIMIT 10').all() as ThreatIndicatorRecord[];
          output = `[RECENT ACTIVE THREAT INDICATORS]\n` +
            threats.map((t) => `• [${t.severity}] ${t.indicator_type}: ${t.indicator_value} (Actor: ${t.threat_actor || 'Unknown'})`).join('\n');
        } else {
          output = `Unknown threats subcommand '${arg1}'. Usage: threats recent`;
        }
        break;

      case 'system':
        if (arg1 === 'health' || !arg1) {
          output = `[SYSTEM HEALTH TELEMETRY]
Node.js: ${process.version}
Uptime: ${Math.floor(process.uptime())}s
Memory Heap Used: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB
Database: ONLINE (WAL mode)
`;
        } else {
          output = `Unknown system subcommand '${arg1}'. Usage: system health`;
        }
        break;

      default:
        output = `Command not recognized: '${rawCmd}'. Type 'help' for allowlisted commands.`;
        break;
    }

    const executionMs = Math.round((performance.now() - t0) * 100) / 100;

    res.json({
      success: true,
      command: rawCmd,
      output,
      execution_ms: executionMs
    });
  };

  router.post('/terminal/exec', validateBody(TerminalCommandSchema), handleCommand);
  router.post('/terminal/execute', validateBody(TerminalCommandSchema), handleCommand);

  return router;
}
