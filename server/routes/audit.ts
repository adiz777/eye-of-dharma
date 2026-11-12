// server/routes/audit.ts
// Read-only tamper-evident audit log stream

import { Router } from 'express';
import type Database from 'better-sqlite3';
import type { AuditEventRecord } from '../db/schema.js';

export function createAuditRouter(db: Database.Database): Router {
  const router = Router();

  // List audit events
  router.get('/audit', (req, res) => {
    const { action, actor, limit = '50', offset = '0' } = req.query;
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (action && typeof action === 'string') {
      conditions.push('action = ?');
      params.push(action);
    }
    if (actor && typeof actor === 'string') {
      conditions.push('actor = ?');
      params.push(actor);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as total FROM audit_events ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM audit_events ${whereClause} ORDER BY timestamp DESC LIMIT ? OFFSET ?`).all(...params, l, o) as AuditEventRecord[];

    const parsedItems = items.map((a) => ({
      ...a,
      details: typeof a.details === 'string' ? JSON.parse(a.details || '{}') : a.details
    }));

    res.json({
      success: true,
      items: parsedItems,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  return router;
}
