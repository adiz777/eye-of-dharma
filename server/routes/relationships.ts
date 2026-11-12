// server/routes/relationships.ts
// Entity Relationship Graph edges API

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { CreateRelationshipSchema, validateBody } from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import type { RelationshipRecord } from '../db/schema.js';

export function createRelationshipsRouter(db: Database.Database): Router {
  const router = Router();

  // List relationships
  router.get('/relationships', (req, res) => {
    const { source_id, target_id, limit = '50', offset = '0' } = req.query;
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (source_id && typeof source_id === 'string') {
      conditions.push('source_entity_id = ?');
      params.push(source_id);
    }
    if (target_id && typeof target_id === 'string') {
      conditions.push('target_entity_id = ?');
      params.push(target_id);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as total FROM relationships ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM relationships ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as RelationshipRecord[];

    res.json({
      success: true,
      items,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // Create relationship
  router.post('/relationships', validateBody(CreateRelationshipSchema), (req, res) => {
    const body = req.body;
    const id = `rel-${crypto.randomUUID()}`;
    const isSynthetic = body.is_synthetic ? 1 : 0;

    // Verify source and target entities exist
    const source = db.prepare('SELECT id FROM entities WHERE id = ?').get(body.source_entity_id);
    const target = db.prepare('SELECT id FROM entities WHERE id = ?').get(body.target_entity_id);

    if (!source || !target) {
      res.status(400).json({
        success: false,
        error: { code: 'INVALID_ENTITY_REFERENCE', message: 'Source or target entity does not exist' }
      });
      return;
    }

    const stmt = db.prepare(`
      INSERT INTO relationships (
        id, source_entity_id, target_entity_id, relation_type, confidence,
        evidence_id, status, notes, is_synthetic, created_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      )
    `);

    stmt.run(
      id,
      body.source_entity_id,
      body.target_entity_id,
      body.relation_type,
      body.confidence ?? 0.5,
      body.evidence_id || null,
      body.status || 'INFERRED',
      body.notes || null,
      isSynthetic
    );

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'RELATIONSHIP_CREATED',
      entity_type: 'RELATIONSHIP',
      entity_id: id,
      details: {
        source_id: body.source_entity_id,
        target_id: body.target_entity_id,
        relation_type: body.relation_type
      },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM relationships WHERE id = ?').get(id) as RelationshipRecord;

    res.status(201).json({
      success: true,
      data: created
    });
  });

  return router;
}
