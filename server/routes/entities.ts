// server/routes/entities.ts
// Entity management and graph neighborhood endpoints

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { CreateEntitySchema, validateBody } from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import type { EntityRecord, RelationshipRecord } from '../db/schema.js';

export function createEntitiesRouter(db: Database.Database): Router {
  const router = Router();

  // Search/List entities
  router.get('/entities', (req, res) => {
    const { case_id, type, min_risk, limit = '50', offset = '0' } = req.query;
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (case_id && typeof case_id === 'string') {
      conditions.push('case_id = ?');
      params.push(case_id);
    }
    if (type && typeof type === 'string') {
      const normalizedType = type === 'IP' ? 'IP_ADDRESS' : type;
      conditions.push('type = ?');
      params.push(normalizedType);
    }
    if (min_risk !== undefined) {
      const risk = parseInt(String(min_risk), 10);
      if (!isNaN(risk)) {
        conditions.push('risk_score >= ?');
        params.push(risk);
      }
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as total FROM entities ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM entities ${whereClause} ORDER BY risk_score DESC, created_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as EntityRecord[];

    const parsedItems = items.map((e) => ({
      ...e,
      metadata: typeof e.metadata === 'string' ? JSON.parse(e.metadata || '{}') : e.metadata
    }));

    res.json({
      success: true,
      items: parsedItems,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // Create entity
  router.post('/entities', validateBody(CreateEntitySchema), (req, res) => {
    const body = req.body;
    const id = `ent-${crypto.randomUUID()}`;
    const metadataStr = JSON.stringify(body.metadata || {});
    const isSynthetic = body.is_synthetic ? 1 : 0;

    const stmt = db.prepare(`
      INSERT INTO entities (
        id, case_id, name, type, value, risk_score, metadata,
        first_observed_at, last_observed_at, is_synthetic, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      )
    `);

    stmt.run(
      id,
      body.case_id || null,
      body.name,
      body.type,
      body.value,
      body.risk_score ?? 0,
      metadataStr,
      isSynthetic
    );

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'ENTITY_CREATED',
      entity_type: 'ENTITY',
      entity_id: id,
      details: { name: body.name, type: body.type, value: body.value },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM entities WHERE id = ?').get(id) as EntityRecord;

    res.status(201).json({
      success: true,
      data: {
        ...created,
        metadata: JSON.parse(created.metadata || '{}')
      }
    });
  });

  // Get entity by ID
  router.get('/entities/:id', (req, res) => {
    const { id } = req.params;
    const item = db.prepare('SELECT * FROM entities WHERE id = ?').get(id) as EntityRecord | undefined;

    if (!item) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Entity with id '${id}' not found` }
      });
      return;
    }

    res.json({
      success: true,
      data: {
        ...item,
        metadata: JSON.parse(item.metadata || '{}')
      }
    });
  });

  // Cytoscape.js neighborhood graph for single entity
  router.get('/entities/:id/graph', (req, res) => {
    const { id } = req.params;
    const targetEntity = db.prepare('SELECT * FROM entities WHERE id = ?').get(id) as EntityRecord | undefined;

    if (!targetEntity) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Entity with id '${id}' not found` }
      });
      return;
    }

    // Find all relationships touching this entity
    const rels = db.prepare(`
      SELECT * FROM relationships
      WHERE source_entity_id = ? OR target_entity_id = ?
    `).all(id, id) as RelationshipRecord[];

    const neighborIds = new Set<string>([id]);
    for (const r of rels) {
      neighborIds.add(r.source_entity_id);
      neighborIds.add(r.target_entity_id);
    }

    const placeholders = Array.from(neighborIds).map(() => '?').join(',');
    const entities = db.prepare(`SELECT * FROM entities WHERE id IN (${placeholders})`).all(...Array.from(neighborIds)) as EntityRecord[];

    const nodes = entities.map((e) => ({
      data: {
        id: e.id,
        label: e.name,
        type: e.type,
        value: e.value,
        riskScore: e.risk_score
      }
    }));

    const edges = rels.map((r) => ({
      data: {
        id: r.id,
        source: r.source_entity_id,
        target: r.target_entity_id,
        label: r.relation_type,
        confidence: r.confidence,
        status: r.status
      }
    }));

    res.json({
      success: true,
      elements: {
        nodes,
        edges
      }
    });
  });

  return router;
}
