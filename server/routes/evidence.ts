// server/routes/evidence.ts
// Evidence Ledger API: Ingestion, SHA-256 fingerprinting, provenance preservation

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { IngestEvidenceSchema, validateBody } from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import type { EvidenceRecord } from '../db/schema.js';

export function createEvidenceRouter(db: Database.Database): Router {
  const router = Router();

  // Query evidence ledger
  router.get('/evidence', (req, res) => {
    const { case_id, source_type, limit = '50', offset = '0' } = req.query;
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (case_id && typeof case_id === 'string') {
      conditions.push('case_id = ?');
      params.push(case_id);
    }
    if (source_type && typeof source_type === 'string') {
      conditions.push('source_type = ?');
      params.push(source_type);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as total FROM evidence_ledger ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM evidence_ledger ${whereClause} ORDER BY retrieved_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as EvidenceRecord[];

    res.json({
      success: true,
      items,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // Ingest new immutable evidence
  router.post('/evidence', validateBody(IngestEvidenceSchema), (req, res) => {
    const body = req.body;
    const id = `ev-${crypto.randomUUID()}`;
    const fingerprint = crypto.createHash('sha256').update(body.raw_content, 'utf8').digest('hex');
    const parsedStr = body.parsed_content ? JSON.stringify(body.parsed_content) : null;
    const isSynthetic = body.is_synthetic ? 1 : 0;

    const stmt = db.prepare(`
      INSERT INTO evidence_ledger (
        id, case_id, source_url, source_type, source_title,
        content_fingerprint, raw_content, parsed_content,
        verification_status, confidence_score, retrieved_at,
        published_at, recorded_by, is_synthetic, notes, immutable_lock
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        ?, ?, ?, ?, 1
      )
    `);

    stmt.run(
      id,
      body.case_id || null,
      body.source_url,
      body.source_type,
      body.source_title,
      fingerprint,
      body.raw_content,
      parsedStr,
      body.verification_status || 'Unverified',
      body.confidence_score ?? 0.5,
      body.published_at || null,
      'COLLECTOR',
      isSynthetic,
      body.notes || null
    );

    recordAuditEvent(db, {
      actor: 'COLLECTOR',
      action: 'EVIDENCE_INGESTED',
      entity_type: 'EVIDENCE',
      entity_id: id,
      details: {
        source_url: body.source_url,
        source_title: body.source_title,
        fingerprint
      },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(id) as EvidenceRecord;

    res.status(201).json({
      success: true,
      data: created
    });
  });

  // Get evidence item by ID
  router.get('/evidence/:id', (req, res) => {
    const { id } = req.params;
    const item = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(id) as EvidenceRecord | undefined;

    if (!item) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Evidence item with id '${id}' not found` }
      });
      return;
    }

    res.json({
      success: true,
      data: item
    });
  });

  return router;
}
