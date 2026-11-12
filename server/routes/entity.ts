// server/routes/entity.ts
// Public-source entity lookup (person / organisation / username). Passive, audited, minimal data kept.

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { EntityQuerySchema, validateBody } from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import { runEntityLookup, type SourceResult } from '../connectors/entity_sources.js';

export function createEntityRouter(
  db: Database.Database,
  lookup: (type: any, target: string) => Promise<SourceResult[]> = runEntityLookup
): Router {
  const router = Router();

  router.post('/investigate/entity', validateBody(EntityQuerySchema), async (req, res) => {
    const { query_type, target, case_id } = req.body;

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'PUBLIC_ENTITY_QUERY',
      entity_type: query_type,
      entity_id: target,
      details: { query_type, target, case_id, lawful_purpose_confirmed: true },
      ip_address: req.ip
    });

    let sources: SourceResult[];
    try {
      sources = await lookup(query_type, target);
    } catch (err) {
      res.status(400).json({ success: false, error: { code: 'INVALID_TARGET', message: err instanceof Error ? err.message : String(err) } });
      return;
    }

    const found = sources.some((s) => s.status === 'found');
    let evidenceId: string | null = null;
    if (case_id && found) {
      const raw = JSON.stringify({ query_type, target, sources });
      const fingerprint = crypto.createHash('sha256').update(raw).digest('hex');
      const existing = db.prepare('SELECT id FROM evidence_ledger WHERE case_id = ? AND content_fingerprint = ?').get(case_id, fingerprint) as { id: string } | undefined;
      if (existing) {
        evidenceId = existing.id;
      } else {
        evidenceId = `ev-${crypto.randomUUID()}`;
        db.prepare(`
          INSERT INTO evidence_ledger (id, case_id, source_url, source_type, source_title, content_fingerprint, raw_content, parsed_content,
            verification_status, confidence_score, retrieved_at, published_at, recorded_by, is_synthetic, notes, immutable_lock)
          VALUES (?, ?, ?, 'AGENT_RESEARCH', ?, ?, ?, ?, 'Source-reported', 0.5, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), null, 'NETRA', 0,
            'Public-source name/handle match: a lead, not proof of identity', 1)
        `).run(evidenceId, case_id, `public://entity/${query_type}/${encodeURIComponent(target)}`, `Public-source lookup: ${query_type} ${target}`,
          fingerprint, raw, JSON.stringify({ sources: sources.map((s) => ({ id: s.sourceId, status: s.status, n: s.records.length })) }));
      }
    }

    res.json({
      success: true,
      query_type,
      target,
      passive: true,
      found,
      sources,
      evidence_id: evidenceId,
      caveat: 'Matches are name/handle leads from public sources. A missing record proves nothing; a match does not prove identity.'
    });
  });

  return router;
}
