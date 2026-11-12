// server/routes/threats.ts
// Threat intelligence indicators & IOCs API

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { CreateThreatIndicatorSchema, validateBody } from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import type { ThreatIndicatorRecord } from '../db/schema.js';

export function createThreatsRouter(db: Database.Database): Router {
  const router = Router();

  // List threat indicators
  router.get('/threats', (req, res) => {
    const { type, severity, is_active, limit = '50', offset = '0' } = req.query;
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (type && typeof type === 'string') {
      conditions.push('indicator_type = ?');
      params.push(type);
    }
    if (severity && typeof severity === 'string') {
      conditions.push('severity = ?');
      params.push(severity);
    }
    if (is_active !== undefined) {
      const activeInt = String(is_active) === 'true' || String(is_active) === '1' ? 1 : 0;
      conditions.push('is_active = ?');
      params.push(activeInt);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as total FROM threat_indicators ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM threat_indicators ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as ThreatIndicatorRecord[];

    const parsedItems = items.map((t) => ({
      ...t,
      tags: typeof t.tags === 'string' ? JSON.parse(t.tags || '[]') : t.tags
    }));

    res.json({
      success: true,
      items: parsedItems,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // Create threat indicator
  router.post('/threats', validateBody(CreateThreatIndicatorSchema), (req, res) => {
    const body = req.body;
    const id = `thr-${crypto.randomUUID()}`;
    const tagsJson = JSON.stringify(body.tags || []);
    const isSynthetic = body.is_synthetic ? 1 : 0;

    const stmt = db.prepare(`
      INSERT INTO threat_indicators (
        id, indicator_type, indicator_value, threat_actor, campaign,
        severity, confidence, source, first_seen, last_seen, is_active,
        is_synthetic, tags, description, created_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1,
        ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      )
    `);

    stmt.run(
      id,
      body.indicator_type,
      body.indicator_value,
      body.threat_actor || null,
      body.campaign || null,
      body.severity || 'MEDIUM',
      body.confidence ?? 0.7,
      body.source,
      isSynthetic,
      tagsJson,
      body.description || null
    );

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'THREAT_INDICATOR_CREATED',
      entity_type: 'THREAT',
      entity_id: id,
      details: { type: body.indicator_type, value: body.indicator_value },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM threat_indicators WHERE id = ?').get(id) as ThreatIndicatorRecord;

    res.status(201).json({
      success: true,
      data: {
        ...created,
        tags: JSON.parse(created.tags || '[]')
      }
    });
  });

  return router;
}
