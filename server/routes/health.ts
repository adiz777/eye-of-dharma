// server/routes/health.ts
// Health check and system telemetry endpoints

import { Router } from 'express';
import type Database from 'better-sqlite3';
import { getSyntheticCounts } from '../db/seed.js';

export function createHealthRouter(db: Database.Database): Router {
  const router = Router();
  const startTime = Date.now();

  router.get('/health', (_req, res) => {
    let dbStatus = 'DISCONNECTED';
    let dbLatencyMs = 0;

    try {
      const t0 = performance.now();
      db.prepare('SELECT 1 as ping').get();
      dbLatencyMs = Math.round((performance.now() - t0) * 100) / 100;
      dbStatus = 'CONNECTED';
    } catch {
      dbStatus = 'ERROR';
    }

    const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);

    res.json({
      status: dbStatus === 'CONNECTED' ? 'UP' : 'DEGRADED',
      timestamp: new Date().toISOString(),
      uptime: uptimeSeconds,
      db: {
        status: dbStatus,
        latencyMs: dbLatencyMs,
        engine: 'SQLite-WAL'
      },
      version: '0.1.0'
    });
  });

  router.get('/system/status', (_req, res) => {
    const memory = process.memoryUsage();
    const tables = ['cases', 'evidence_ledger', 'entities', 'relationships', 'threat_indicators', 'feed_records', 'watchlists', 'audit_events', 'agent_runs'];
    const rowCounts: Record<string, number> = {};

    for (const table of tables) {
      try {
        const row = db.prepare(`SELECT COUNT(*) as count FROM ${table}`).get() as { count: number };
        rowCounts[table] = row.count;
      } catch {
        rowCounts[table] = 0;
      }
    }

    const syntheticCounts = getSyntheticCounts(db);

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
      memory: {
        rssMb: Math.round(memory.rss / (1024 * 1024)),
        heapUsedMb: Math.round(memory.heapUsed / (1024 * 1024)),
        heapTotalMb: Math.round(memory.heapTotal / (1024 * 1024))
      },
      tables: rowCounts,
      synthetic_counts: syntheticCounts
    });
  });

  return router;
}
