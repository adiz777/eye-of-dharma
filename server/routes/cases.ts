// server/routes/cases.ts
// Milestone M4: Complete Case Workspace, Evidence Linking, Notes, Cytoscape Graph & Custody API

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import {
  CreateCaseSchema,
  UpdateCaseSchema,
  IngestEvidenceSchema,
  AttachEvidenceSchema,
  CaseNoteSchema,
  CreateCaseEntitySchema,
  CreateCaseRelationshipSchema,
  validateBody
} from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import type {
  CaseRecord,
  EvidenceRecord,
  EntityRecord,
  RelationshipRecord,
  CaseNoteRecord,
  AgentRunRecord
} from '../db/schema.js';

export function createCasesRouter(db: Database.Database): Router {
  const router = Router();

  const sha256 = (val: string) => crypto.createHash('sha256').update(val, 'utf8').digest('hex');

  // Helper to check if a column exists in a table
  const hasColumn = (tableName: string, colName: string): boolean => {
    try {
      const cols = db.prepare(`PRAGMA table_info('${tableName}')`).all() as Array<{ name: string }>;
      return cols.some((c) => c.name === colName);
    } catch {
      return false;
    }
  };

  // ---------------------------------------------------------------------------
  // 1. GET /cases — Filter by status, priority/severity, TLP, text search, pagination
  // ---------------------------------------------------------------------------
  router.get('/cases', (req, res) => {
    const { status, priority, severity, tlp, q, search, limit = '50', offset = '0' } = req.query;
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (status && typeof status === 'string') {
      conditions.push('status = ?');
      params.push(status);
    }

    const prioVal = priority || severity;
    if (prioVal && typeof prioVal === 'string') {
      conditions.push('priority = ?');
      params.push(prioVal);
    }

    if (tlp && typeof tlp === 'string') {
      if (hasColumn('cases', 'tlp')) {
        conditions.push('tlp = ?');
        params.push(tlp);
      } else {
        conditions.push('tags LIKE ?');
        params.push(`%${tlp}%`);
      }
    }

    const searchTerm = q || search;
    if (searchTerm && typeof searchTerm === 'string' && searchTerm.trim().length > 0) {
      const term = `%${searchTerm.trim()}%`;
      conditions.push('(title LIKE ? OR description LIKE ? OR summary LIKE ? OR tags LIKE ?)');
      params.push(term, term, term, term);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const countRow = db.prepare(`SELECT COUNT(*) as total FROM cases ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM cases ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as any[];

    const parsedItems = items.map((c) => ({
      ...c,
      tags: typeof c.tags === 'string' ? JSON.parse(c.tags || '[]') : c.tags,
      tlp: c.tlp || 'TLP:AMBER',
      classification: c.classification || 'UNCLASSIFIED'
    }));

    res.json({
      success: true,
      items: parsedItems,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // ---------------------------------------------------------------------------
  // 2. POST /cases — Create case with title, description, priority, TLP, classification, tags
  // ---------------------------------------------------------------------------
  router.post('/cases', validateBody(CreateCaseSchema), (req, res) => {
    const body = req.body;
    const id = `case-${crypto.randomUUID()}`;
    const tagsJson = JSON.stringify(body.tags || []);
    const isSynthetic = body.is_synthetic ? 1 : 0;
    const tlp = body.tlp || 'TLP:AMBER';
    const classification = body.classification || 'UNCLASSIFIED';

    if (hasColumn('cases', 'tlp')) {
      db.prepare(`
        INSERT INTO cases (id, title, description, priority, lead_analyst, tags, summary, tlp, classification, is_synthetic, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      `).run(id, body.title, body.description || null, body.priority, body.lead_analyst, tagsJson, body.summary || null, tlp, classification, isSynthetic);
    } else {
      db.prepare(`
        INSERT INTO cases (id, title, description, priority, lead_analyst, tags, summary, is_synthetic, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      `).run(id, body.title, body.description || null, body.priority, body.lead_analyst, tagsJson, body.summary || null, isSynthetic);
    }

    const payloadHash = sha256(JSON.stringify({ id, title: body.title, priority: body.priority, tlp, classification }));

    recordAuditEvent(db, {
      actor: body.lead_analyst,
      action: 'CASE_CREATED',
      entity_type: 'CASE',
      entity_id: id,
      details: { title: body.title, priority: body.priority, tlp, classification, content_hash: payloadHash },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as any;

    res.status(201).json({
      success: true,
      data: {
        ...created,
        tags: JSON.parse(created.tags || '[]'),
        tlp: created.tlp || tlp,
        classification: created.classification || classification
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 3. GET /cases/:id — Full case dossier with metrics counts
  // ---------------------------------------------------------------------------
  router.get('/cases/:id', (req, res) => {
    const { id } = req.params;
    const caseRow = db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as any;

    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case with id '${id}' not found` }
      });
      return;
    }

    // Evidence count across direct and junction-linked
    let evidenceCount = 0;
    try {
      const evRow = db.prepare(`
        SELECT COUNT(DISTINCT e.id) as cnt
        FROM evidence_ledger e
        LEFT JOIN case_evidence ce ON e.id = ce.evidence_id
        WHERE e.case_id = ? OR ce.case_id = ?
      `).get(id, id) as { cnt: number };
      evidenceCount = evRow.cnt;
    } catch {
      evidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM evidence_ledger WHERE case_id = ?').get(id) as { cnt: number }).cnt;
    }

    const entityCount = (db.prepare('SELECT COUNT(*) as cnt FROM entities WHERE case_id = ?').get(id) as { cnt: number }).cnt;

    let notesCount = 0;
    try {
      notesCount = (db.prepare('SELECT COUNT(*) as cnt FROM case_notes WHERE case_id = ?').get(id) as { cnt: number }).cnt;
    } catch {
      notesCount = 0;
    }

    let runsCount = 0;
    try {
      runsCount = (db.prepare('SELECT COUNT(*) as cnt FROM agent_runs WHERE case_id = ?').get(id) as { cnt: number }).cnt;
    } catch {
      runsCount = 0;
    }

    res.json({
      success: true,
      data: {
        ...caseRow,
        tags: JSON.parse(caseRow.tags || '[]'),
        tlp: caseRow.tlp || 'TLP:AMBER',
        classification: caseRow.classification || 'UNCLASSIFIED',
        metrics: {
          evidenceCount,
          entityCount,
          notesCount,
          runsCount
        }
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 4. PATCH & PUT /cases/:id — Update case metadata
  // ---------------------------------------------------------------------------
  const updateHandler = (req: import('express').Request, res: import('express').Response) => {
    const { id } = req.params;
    const caseRow = db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as any;

    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case with id '${id}' not found` }
      });
      return;
    }

    const body = req.body;
    const updates: string[] = [];
    const params: (string | null)[] = [];

    if (body.title !== undefined) { updates.push('title = ?'); params.push(body.title); }
    if (body.description !== undefined) { updates.push('description = ?'); params.push(body.description); }
    if (body.status !== undefined) {
      updates.push('status = ?');
      params.push(body.status);
      if (body.status === 'CLOSED' || body.status === 'ARCHIVED') {
        updates.push("closed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')");
      }
    }
    if (body.priority !== undefined) { updates.push('priority = ?'); params.push(body.priority); }
    if (body.lead_analyst !== undefined) { updates.push('lead_analyst = ?'); params.push(body.lead_analyst); }
    if (body.tags !== undefined) { updates.push('tags = ?'); params.push(JSON.stringify(body.tags)); }
    if (body.summary !== undefined) { updates.push('summary = ?'); params.push(body.summary); }

    if (hasColumn('cases', 'tlp')) {
      if (body.tlp !== undefined) { updates.push('tlp = ?'); params.push(body.tlp); }
      if (body.classification !== undefined) { updates.push('classification = ?'); params.push(body.classification); }
    }

    if (updates.length > 0) {
      params.push(id);
      db.prepare(`UPDATE cases SET ${updates.join(', ')} WHERE id = ?`).run(...params);

      const deltaHash = sha256(JSON.stringify(body));
      recordAuditEvent(db, {
        actor: body.lead_analyst || caseRow.lead_analyst,
        action: 'CASE_UPDATED',
        entity_type: 'CASE',
        entity_id: id,
        details: { updates: body, content_hash: deltaHash },
        ip_address: req.ip
      });
    }

    const updated = db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as any;
    res.json({
      success: true,
      data: {
        ...updated,
        tags: JSON.parse(updated.tags || '[]'),
        tlp: updated.tlp || 'TLP:AMBER',
        classification: updated.classification || 'UNCLASSIFIED'
      }
    });
  };

  router.patch('/cases/:id', validateBody(UpdateCaseSchema), updateHandler);
  router.put('/cases/:id', validateBody(UpdateCaseSchema), updateHandler);

  // ---------------------------------------------------------------------------
  // 5. DELETE /cases/:id — Soft-delete / Archive case (non-destructive)
  // ---------------------------------------------------------------------------
  router.delete('/cases/:id', (req, res) => {
    const { id } = req.params;
    const caseRow = db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as any;

    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case with id '${id}' not found` }
      });
      return;
    }

    // Perform non-destructive soft-delete / archival to preserve evidence immutability
    db.prepare(`
      UPDATE cases
      SET status = 'ARCHIVED', closed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ?
    `).run(id);

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'CASE_ARCHIVED',
      entity_type: 'CASE',
      entity_id: id,
      details: { previous_status: caseRow.status, soft_deleted: true },
      ip_address: req.ip
    });

    res.json({
      success: true,
      id,
      status: 'ARCHIVED',
      soft_deleted: true,
      message: 'Case archived successfully; evidence ledger and chain of custody preserved.'
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Evidence Endpoints
  // ---------------------------------------------------------------------------

  // GET /cases/:id/evidence — Read evidence attached to case (direct + junction)
  router.get('/cases/:id/evidence', (req, res) => {
    const { id } = req.params;
    let items: EvidenceRecord[] = [];
    try {
      items = db.prepare(`
        SELECT DISTINCT e.*
        FROM evidence_ledger e
        LEFT JOIN case_evidence ce ON e.id = ce.evidence_id
        WHERE e.case_id = ? OR ce.case_id = ?
        ORDER BY e.retrieved_at DESC
      `).all(id, id) as EvidenceRecord[];
    } catch {
      items = db.prepare('SELECT * FROM evidence_ledger WHERE case_id = ? ORDER BY retrieved_at DESC').all(id) as EvidenceRecord[];
    }
    res.json({ success: true, items, total: items.length });
  });

  // POST /cases/:id/evidence — Direct ingestion of new evidence to case
  router.post('/cases/:id/evidence', validateBody(IngestEvidenceSchema), (req, res) => {
    const { id } = req.params;
    const body = req.body;
    const evidenceId = `ev-${crypto.randomUUID()}`;
    const fingerprint = sha256(body.raw_content);
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
      evidenceId, id, body.source_url, body.source_type, body.source_title,
      fingerprint, body.raw_content, parsedStr,
      body.verification_status || 'Unverified', body.confidence_score ?? 0.5,
      body.published_at || null, 'ANALYST', isSynthetic, body.notes || null
    );

    // Also mirror into case_evidence junction
    try {
      db.prepare(`
        INSERT OR IGNORE INTO case_evidence (id, case_id, evidence_id, attached_by, notes)
        VALUES (?, ?, ?, 'ANALYST', ?)
      `).run(`ce-${crypto.randomUUID()}`, id, evidenceId, body.notes || null);
    } catch { /* optional */ }

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'EVIDENCE_ATTACHED',
      entity_type: 'EVIDENCE',
      entity_id: evidenceId,
      details: { case_id: id, source_title: body.source_title, content_fingerprint: fingerprint },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(evidenceId);
    res.status(201).json({ success: true, data: created });
  });

  // POST /cases/:id/evidence/attach — Attach existing evidence without mutating evidence_ledger
  router.post('/cases/:id/evidence/attach', validateBody(AttachEvidenceSchema), (req, res) => {
    const { id } = req.params;
    const { evidence_id, notes } = req.body;

    const ev = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(evidence_id) as EvidenceRecord | undefined;
    if (!ev) {
      res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: `Evidence '${evidence_id}' not found` } });
      return;
    }

    const junctionId = `ce-${crypto.randomUUID()}`;
    db.prepare(`
      INSERT OR IGNORE INTO case_evidence (id, case_id, evidence_id, attached_by, notes)
      VALUES (?, ?, ?, 'ANALYST', ?)
    `).run(junctionId, id, evidence_id, notes || null);

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'EVIDENCE_ATTACHED',
      entity_type: 'EVIDENCE',
      entity_id: evidence_id,
      details: { case_id: id, source_title: ev.source_title, content_fingerprint: ev.content_fingerprint, method: 'JUNCTION_ATTACH' },
      ip_address: req.ip
    });

    res.json({
      success: true,
      case_id: id,
      evidence_id,
      attached: true
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Analyst Notes Endpoints (Append-Only)
  // ---------------------------------------------------------------------------

  // GET /cases/:id/notes — Retrieve append-only analyst notes
  router.get('/cases/:id/notes', (req, res) => {
    const { id } = req.params;
    const { sort = 'asc', limit = '100', offset = '0' } = req.query;

    const direction = String(sort).toLowerCase() === 'desc' ? 'DESC' : 'ASC';
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 100, 1), 200);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    try {
      const countRow = db.prepare('SELECT COUNT(*) as count FROM case_notes WHERE case_id = ?').get(id) as { count: number };
      const notes = db.prepare(`
        SELECT * FROM case_notes
        WHERE case_id = ?
        ORDER BY created_at ${direction}
        LIMIT ? OFFSET ?
      `).all(id, l, o) as CaseNoteRecord[];

      res.json({
        success: true,
        case_id: id,
        items: notes.map((n) => ({
          ...n,
          tags: typeof n.tags === 'string' ? JSON.parse(n.tags || '[]') : n.tags
        })),
        total: countRow.count,
        limit: l,
        offset: o
      });
    } catch {
      res.json({ success: true, case_id: id, items: [], total: 0 });
    }
  });

  // POST /cases/:id/notes — Append new immutable analyst note
  router.post('/cases/:id/notes', validateBody(CaseNoteSchema), (req, res) => {
    const { id } = req.params;
    const body = req.body;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    let version = 1;
    if (body.parent_note_id) {
      const parent = db.prepare('SELECT id, version, case_id FROM case_notes WHERE id = ?').get(body.parent_note_id) as CaseNoteRecord | undefined;
      if (!parent) {
        res.status(400).json({
          success: false,
          error: { code: 'INVALID_PARENT_NOTE', message: `Parent note '${body.parent_note_id}' does not exist.` }
        });
        return;
      }
      if (parent.case_id !== id) {
        res.status(400).json({
          success: false,
          error: { code: 'CROSS_CASE_AMENDMENT_PROHIBITED', message: 'Parent note does not belong to this case.' }
        });
        return;
      }
      version = parent.version + 1;
    }

    const noteId = `note-${crypto.randomUUID()}`;
    const contentHash = sha256(body.content);
    const tagsJson = JSON.stringify(body.tags || []);

    db.prepare(`
      INSERT INTO case_notes (id, case_id, author, content, content_hash, tags, parent_note_id, version, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    `).run(noteId, id, body.author, body.content, contentHash, tagsJson, body.parent_note_id || null, version);

    recordAuditEvent(db, {
      actor: body.author,
      action: body.parent_note_id ? 'NOTE_AMENDED' : 'NOTE_ADDED',
      entity_type: 'NOTE',
      entity_id: noteId,
      details: { case_id: id, version, parent_note_id: body.parent_note_id || null, content_hash: contentHash },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM case_notes WHERE id = ?').get(noteId) as CaseNoteRecord;
    res.status(201).json({
      success: true,
      data: {
        ...created,
        tags: JSON.parse(created.tags || '[]')
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 8. Case Entities & Relationships Endpoints
  // ---------------------------------------------------------------------------

  // GET /cases/:id/entities — Entities belonging to this case
  router.get('/cases/:id/entities', (req, res) => {
    const { id } = req.params;
    const { type, min_risk, limit = '50', offset = '0' } = req.query;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = ['case_id = ?'];
    const params: (string | number)[] = [id];

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

    const whereClause = `WHERE ${conditions.join(' AND ')}`;
    const countRow = db.prepare(`SELECT COUNT(*) as total FROM entities ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM entities ${whereClause} ORDER BY risk_score DESC, created_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as EntityRecord[];

    res.json({
      success: true,
      case_id: id,
      items: items.map((e) => ({
        ...e,
        metadata: typeof e.metadata === 'string' ? JSON.parse(e.metadata || '{}') : e.metadata
      })),
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // POST /cases/:id/entities — Create and associate entity to case
  router.post('/cases/:id/entities', validateBody(CreateCaseEntitySchema), (req, res) => {
    const { id } = req.params;
    const body = req.body;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    const entityId = `ent-${crypto.randomUUID()}`;
    const metadataStr = JSON.stringify(body.metadata || {});
    const isSynthetic = body.is_synthetic ? 1 : 0;

    db.prepare(`
      INSERT INTO entities (
        id, case_id, name, type, value, risk_score, metadata,
        first_observed_at, last_observed_at, is_synthetic, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      )
    `).run(entityId, id, body.name, body.type, body.value, body.risk_score ?? 0, metadataStr, isSynthetic);

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'ENTITY_CREATED',
      entity_type: 'ENTITY',
      entity_id: entityId,
      details: { case_id: id, name: body.name, type: body.type, value: body.value },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM entities WHERE id = ?').get(entityId) as EntityRecord;
    res.status(201).json({
      success: true,
      data: {
        ...created,
        metadata: JSON.parse(created.metadata || '{}')
      }
    });
  });

  // GET /cases/:id/relationships — Relationships touching entities in this case
  router.get('/cases/:id/relationships', (req, res) => {
    const { id } = req.params;
    const { status, relation_type, limit = '50', offset = '0' } = req.query;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    const conditions: string[] = [
      '(source_entity_id IN (SELECT id FROM entities WHERE case_id = ?) OR target_entity_id IN (SELECT id FROM entities WHERE case_id = ?))'
    ];
    const params: (string | number)[] = [id, id];

    if (status && typeof status === 'string') {
      conditions.push('status = ?');
      params.push(status);
    }
    if (relation_type && typeof relation_type === 'string') {
      conditions.push('relation_type = ?');
      params.push(relation_type);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;
    const countRow = db.prepare(`SELECT COUNT(*) as total FROM relationships ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM relationships ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as RelationshipRecord[];

    res.json({
      success: true,
      case_id: id,
      items,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // POST /cases/:id/relationships — Create relationship touching case entities
  router.post('/cases/:id/relationships', validateBody(CreateCaseRelationshipSchema), (req, res) => {
    const { id } = req.params;
    const body = req.body;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    const source = db.prepare('SELECT id FROM entities WHERE id = ?').get(body.source_entity_id);
    const target = db.prepare('SELECT id FROM entities WHERE id = ?').get(body.target_entity_id);

    if (!source || !target) {
      res.status(400).json({
        success: false,
        error: { code: 'INVALID_ENTITY_REFERENCE', message: 'Source or target entity does not exist' }
      });
      return;
    }

    const relId = `rel-${crypto.randomUUID()}`;
    const isSynthetic = body.is_synthetic ? 1 : 0;

    db.prepare(`
      INSERT INTO relationships (
        id, source_entity_id, target_entity_id, relation_type, confidence,
        evidence_id, status, notes, is_synthetic, created_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      )
    `).run(
      relId,
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
      entity_id: relId,
      details: { case_id: id, source: body.source_entity_id, target: body.target_entity_id, status: body.status },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM relationships WHERE id = ?').get(relId);
    res.status(201).json({ success: true, data: created });
  });

  // ---------------------------------------------------------------------------
  // 9. Hardened GET /cases/:id/graph (Guaranteed Cytoscape Integrity & Styling)
  // ---------------------------------------------------------------------------
  router.get('/cases/:id/graph', (req, res) => {
    const { id } = req.params;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    // 1. Direct case entities
    const caseEntities = db.prepare('SELECT * FROM entities WHERE case_id = ?').all(id) as EntityRecord[];
    const caseEntityIds = new Set(caseEntities.map((e) => e.id));

    // 2. Query relationships touching any case entity
    let relationships: RelationshipRecord[] = [];
    if (caseEntityIds.size > 0) {
      const placeholders = Array.from(caseEntityIds).map(() => '?').join(',');
      relationships = db.prepare(`
        SELECT * FROM relationships
        WHERE source_entity_id IN (${placeholders}) OR target_entity_id IN (${placeholders})
      `).all(...caseEntityIds, ...caseEntityIds) as RelationshipRecord[];
    }

    // 3. Resolve all external neighbor entities to guarantee Cytoscape referential integrity
    const allReferencedNodeIds = new Set<string>(caseEntityIds);
    for (const r of relationships) {
      allReferencedNodeIds.add(r.source_entity_id);
      allReferencedNodeIds.add(r.target_entity_id);
    }

    const missingNodeIds = Array.from(allReferencedNodeIds).filter((nodeId) => !caseEntityIds.has(nodeId));
    let externalEntities: EntityRecord[] = [];
    if (missingNodeIds.length > 0) {
      const extPlaceholders = missingNodeIds.map(() => '?').join(',');
      externalEntities = db.prepare(`
        SELECT * FROM entities WHERE id IN (${extPlaceholders})
      `).all(...missingNodeIds) as EntityRecord[];
    }

    const allEntities = [...caseEntities, ...externalEntities];

    // Visual styles for confidence
    const confidenceStyleMap: Record<string, { color: string; lineStyle: string }> = {
      VERIFIED: { color: '#00E5FF', lineStyle: 'solid' },
      INFERRED: { color: '#FFA726', lineStyle: 'dashed' },
      HYPOTHESIS: { color: '#D4AF37', lineStyle: 'dotted' }
    };

    // 4. Cytoscape elements formatting
    const nodes = allEntities.map((e) => ({
      data: {
        id: e.id,
        label: e.name,
        type: e.type,
        value: e.value,
        riskScore: e.risk_score,
        isExternal: e.case_id !== id,
        metadata: typeof e.metadata === 'string' ? JSON.parse(e.metadata || '{}') : e.metadata
      }
    }));

    const edges = relationships.map((r) => {
      const style = confidenceStyleMap[r.status] || confidenceStyleMap.INFERRED;
      return {
        data: {
          id: r.id,
          source: r.source_entity_id,
          target: r.target_entity_id,
          label: r.relation_type,
          confidence: r.confidence,
          status: r.status,
          evidence_id: r.evidence_id,
          notes: r.notes,
          color: style.color,
          lineStyle: style.lineStyle
        }
      };
    });

    res.json({
      success: true,
      case_id: id,
      nodes,
      edges,
      elements: {
        nodes,
        edges
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 10. 4-Swimlane Investigation Timeline (Normalized Zulu UTC Timestamps)
  // ---------------------------------------------------------------------------
  router.get('/cases/:id/timeline', (req, res) => {
    const { id } = req.params;
    const { sort = 'desc' } = req.query;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    // 1. Swimlane: EVIDENCE (direct + junction)
    let evidenceRows: any[] = [];
    try {
      evidenceRows = db.prepare(`
        SELECT DISTINCT e.id, e.source_title, e.source_type, e.source_url, e.content_fingerprint,
               e.verification_status, e.confidence_score, e.retrieved_at, e.published_at, e.recorded_by
        FROM evidence_ledger e
        LEFT JOIN case_evidence ce ON e.id = ce.evidence_id
        WHERE e.case_id = ? OR ce.case_id = ?
      `).all(id, id);
    } catch {
      evidenceRows = db.prepare(`
        SELECT id, source_title, source_type, source_url, content_fingerprint,
               verification_status, confidence_score, retrieved_at, published_at, recorded_by
        FROM evidence_ledger WHERE case_id = ?
      `).all(id);
    }

    const evidenceItems = evidenceRows.map((e) => ({
      id: e.id,
      swimlane: 'EVIDENCE',
      category: 'EVIDENCE',
      title: e.source_title,
      timestamp: new Date(e.published_at || e.retrieved_at).toISOString(),
      verification_badge: e.verification_status,
      confidence_score: e.confidence_score,
      metadata: {
        source_type: e.source_type,
        source_url: e.source_url,
        content_fingerprint: e.content_fingerprint,
        recorded_by: e.recorded_by
      }
    }));

    // 2. Swimlane: THREATS (Correlated by case entity IOC values)
    const threatRows = db.prepare(`
      SELECT DISTINCT t.id, t.indicator_type, t.indicator_value, t.threat_actor,
                      t.campaign, t.severity, t.confidence, t.source, t.first_seen, t.created_at
      FROM threat_indicators t
      WHERE t.indicator_value IN (SELECT value FROM entities WHERE case_id = ?)
    `).all(id) as Array<{
      id: string;
      indicator_type: string;
      indicator_value: string;
      threat_actor: string | null;
      campaign: string | null;
      severity: string;
      confidence: number;
      source: string;
      first_seen: string;
      created_at: string;
    }>;

    const threatItems = threatRows.map((t) => ({
      id: t.id,
      swimlane: 'THREATS',
      category: 'THREAT_INDICATOR',
      title: `[${t.indicator_type}] ${t.indicator_value}`,
      timestamp: new Date(t.first_seen || t.created_at).toISOString(),
      verification_badge: t.severity,
      confidence_score: t.confidence,
      metadata: {
        indicator_type: t.indicator_type,
        indicator_value: t.indicator_value,
        threat_actor: t.threat_actor,
        campaign: t.campaign,
        source: t.source
      }
    }));

    // 3. Swimlane: AGENT_RUNS
    const agentRunRows = db.prepare(`
      SELECT id, agent_name, status, output_summary, token_usage,
             execution_time_ms, started_at, completed_at, citations
      FROM agent_runs
      WHERE case_id = ?
    `).all(id) as Array<{
      id: string;
      agent_name: string;
      status: string;
      output_summary: string | null;
      token_usage: number;
      execution_time_ms: number;
      started_at: string;
      completed_at: string | null;
      citations: string;
    }>;

    const agentRunItems = agentRunRows.map((r) => ({
      id: r.id,
      swimlane: 'AGENT_RUNS',
      category: 'AGENT_RUN',
      title: `[${r.agent_name}] ${r.status}: ${r.output_summary ? r.output_summary.slice(0, 100) : 'Investigation milestone'}`,
      timestamp: new Date(r.completed_at || r.started_at).toISOString(),
      verification_badge: r.status,
      confidence_score: 1.0,
      metadata: {
        agent_name: r.agent_name,
        status: r.status,
        token_usage: r.token_usage,
        execution_time_ms: r.execution_time_ms,
        citations: JSON.parse(r.citations || '[]')
      }
    }));

    // 4. Swimlane: ANALYST_NOTES
    let noteRows: CaseNoteRecord[] = [];
    try {
      noteRows = db.prepare(`
        SELECT id, author, content, parent_note_id, version, tags, created_at
        FROM case_notes
        WHERE case_id = ?
      `).all(id) as CaseNoteRecord[];
    } catch {
      noteRows = [];
    }

    const noteItems = noteRows.map((n) => ({
      id: n.id,
      swimlane: 'ANALYST_NOTES',
      category: 'ANALYST_NOTE',
      title: `Note by ${n.author}${n.version > 1 ? ` (v${n.version} Amendment)` : ''}`,
      content: n.content,
      timestamp: new Date(n.created_at).toISOString(),
      verification_badge: n.version === 1 ? 'ORIGINAL' : 'AMENDMENT',
      confidence_score: 1.0,
      metadata: {
        author: n.author,
        version: n.version,
        parent_note_id: n.parent_note_id,
        tags: typeof n.tags === 'string' ? JSON.parse(n.tags || '[]') : n.tags
      }
    }));

    // Synthesize and sort chronologically
    const allEvents = [...evidenceItems, ...threatItems, ...agentRunItems, ...noteItems];
    const isDesc = String(sort).toLowerCase() !== 'asc';

    allEvents.sort((a, b) => {
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return isDesc ? tb - ta : ta - tb;
    });

    res.json({
      success: true,
      case_id: id,
      total: allEvents.length,
      swimlanes: {
        EVIDENCE: evidenceItems,
        THREATS: threatItems,
        AGENT_RUNS: agentRunItems,
        ANALYST_NOTES: noteItems
      },
      items: allEvents
    });
  });

  // ---------------------------------------------------------------------------
  // 11. Chain of Custody Endpoint (Cryptographic Audit Trail)
  // ---------------------------------------------------------------------------
  router.get('/cases/:id/custody', (req, res) => {
    const { id } = req.params;

    const caseRow = db.prepare('SELECT id FROM cases WHERE id = ?').get(id);
    if (!caseRow) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Case '${id}' not found` }
      });
      return;
    }

    const events = db.prepare(`
      SELECT * FROM audit_events
      WHERE entity_id = ?
         OR (entity_type = 'CASE' AND entity_id = ?)
         OR details LIKE ?
         OR details LIKE ?
      ORDER BY timestamp DESC
    `).all(id, id, `%"case_id":"${id}"%`, `%"caseId":"${id}"%`) as any[];

    const custodyChain = events.map((ev) => {
      let parsedDetails: any = {};
      try {
        parsedDetails = typeof ev.details === 'string' ? JSON.parse(ev.details) : ev.details;
      } catch {
        parsedDetails = {};
      }

      const targetHash = parsedDetails.content_fingerprint || parsedDetails.content_hash || parsedDetails.fingerprint || parsedDetails.sha256 || sha256(ev.id + ev.action);

      return {
        id: ev.id,
        timestamp: new Date(ev.timestamp).toISOString(),
        actor: ev.actor,
        action: ev.action,
        entity_type: ev.entity_type,
        entity_id: ev.entity_id,
        target_hash: targetHash,
        ip_address: ev.ip_address || '127.0.0.1',
        status: ev.status,
        details: parsedDetails
      };
    });

    res.json({
      success: true,
      case_id: id,
      total: custodyChain.length,
      custody_chain: custodyChain
    });
  });

  // ---------------------------------------------------------------------------
  // 12. GET /cases/:id/runs — Multi-Agent execution history for case
  // ---------------------------------------------------------------------------
  router.get('/cases/:id/runs', (req, res) => {
    const { id } = req.params;
    const runs = db.prepare('SELECT * FROM agent_runs WHERE case_id = ? ORDER BY started_at DESC').all(id) as AgentRunRecord[];
    res.json({
      success: true,
      items: runs.map((r) => ({
        ...r,
        input_parameters: JSON.parse(r.input_parameters || '{}'),
        execution_plan: r.execution_plan ? JSON.parse(r.execution_plan) : null,
        citations: JSON.parse(r.citations || '[]')
      }))
    });
  });

  // ---------------------------------------------------------------------------
  // 13. POST /cases/:id/export — Multi-format Case Report Generator
  // ---------------------------------------------------------------------------
  router.post('/cases/:id/export', (req, res) => {
    const { id } = req.params;
    const format = (req.body?.format || 'json').toLowerCase();

    const caseRow = db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as CaseRecord | undefined;
    if (!caseRow) {
      res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Case not found' } });
      return;
    }

    let evidence: any[] = [];
    try {
      evidence = db.prepare(`
        SELECT DISTINCT e.* FROM evidence_ledger e
        LEFT JOIN case_evidence ce ON e.id = ce.evidence_id
        WHERE e.case_id = ? OR ce.case_id = ?
      `).all(id, id);
    } catch {
      evidence = db.prepare('SELECT * FROM evidence_ledger WHERE case_id = ?').all(id);
    }

    const entities = db.prepare('SELECT * FROM entities WHERE case_id = ?').all(id);

    if (format === 'html') {
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${caseRow.title} - Investigation Dossier</title>
  <style>
    body { font-family: monospace; background: #0A0D14; color: #E2E8F0; padding: 2rem; }
    h1 { color: #00E5FF; border-bottom: 2px solid #1E293B; }
    .badge { background: #1E293B; color: #D4AF37; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>[EYE OF DHARMA] Case Dossier: ${caseRow.title}</h1>
  <p><strong>Case ID:</strong> ${caseRow.id} | <span class="badge">${caseRow.priority}</span> | Status: ${caseRow.status}</p>
  <p><strong>Lead Analyst:</strong> ${caseRow.lead_analyst}</p>
  <p>${caseRow.description || ''}</p>
  <h2>Evidence Ledger (${evidence.length} entries)</h2>
  <ul>
    ${evidence.map((e: any) => `<li>[${e.verification_status}] ${e.source_title} (${(e.content_fingerprint || '').substring(0, 16)}...)</li>`).join('')}
  </ul>
</body>
</html>`;
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
      return;
    }

    if (format === 'csv') {
      const header = 'id,case_id,source_title,source_url,verification_status,confidence_score,content_fingerprint\n';
      const rows = evidence
        .map(
          (e: any) =>
            `"${e.id}","${e.case_id || id}","${(e.source_title || '').replace(/"/g, '""')}","${e.source_url}","${e.verification_status}",${e.confidence_score},"${e.content_fingerprint}"`
        )
        .join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="case-${id}.csv"`);
      res.send(header + rows);
      return;
    }

    // Default JSON / STIX-like
    res.json({
      success: true,
      format,
      dossier: {
        case: { ...caseRow, tags: JSON.parse(caseRow.tags || '[]') },
        evidence,
        entities
      }
    });
  });

  return router;
}
