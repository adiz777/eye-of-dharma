// server/routes/watchlists.ts
// Watchlist configuration and management endpoints

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { CreateWatchlistSchema, UpdateWatchlistSchema, validateBody } from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import type { WatchlistRecord } from '../db/schema.js';

export function createWatchlistsRouter(db: Database.Database): Router {
  const router = Router();

  // List watchlists
  router.get('/watchlists', (req, res) => {
    const { is_active } = req.query;
    let query = 'SELECT * FROM watchlists';
    const params: (number | string)[] = [];

    if (is_active !== undefined) {
      const activeInt = String(is_active) === 'true' || String(is_active) === '1' ? 1 : 0;
      query += ' WHERE is_active = ?';
      params.push(activeInt);
    }

    query += ' ORDER BY created_at DESC';
    const items = db.prepare(query).all(...params) as WatchlistRecord[];

    res.json({
      success: true,
      items
    });
  });

  // Create watchlist
  router.post('/watchlists', validateBody(CreateWatchlistSchema), (req, res) => {
    const body = req.body;
    const id = `wl-${crypto.randomUUID()}`;
    const isSynthetic = body.is_synthetic ? 1 : 0;
    const isActive = body.is_active ? 1 : 0;

    const stmt = db.prepare(`
      INSERT INTO watchlists (
        id, name, description, target_type, pattern, alert_severity,
        is_active, match_count, last_matched_at, created_at, updated_at, is_synthetic
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, 0, null, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?
      )
    `);

    stmt.run(
      id,
      body.name,
      body.description || null,
      body.target_type,
      body.pattern,
      body.alert_severity || 'MEDIUM',
      isActive,
      isSynthetic
    );

    recordAuditEvent(db, {
      actor: 'ANALYST',
      action: 'WATCHLIST_CREATED',
      entity_type: 'WATCHLIST',
      entity_id: id,
      details: { name: body.name, pattern: body.pattern, target_type: body.target_type },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM watchlists WHERE id = ?').get(id) as WatchlistRecord;

    res.status(201).json({
      success: true,
      data: created
    });
  });

  // Toggle/update watchlist status
  router.patch('/watchlists/:id', validateBody(UpdateWatchlistSchema), (req, res) => {
    const { id } = req.params;
    const body = req.body;
    const item = db.prepare('SELECT * FROM watchlists WHERE id = ?').get(id) as WatchlistRecord | undefined;

    if (!item) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Watchlist with id '${id}' not found` }
      });
      return;
    }

    const isActive = body.is_active ? 1 : 0;
    db.prepare('UPDATE watchlists SET is_active = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?').run(isActive, id);

    const updated = db.prepare('SELECT * FROM watchlists WHERE id = ?').get(id) as WatchlistRecord;

    res.json({
      success: true,
      data: updated
    });
  });

  return router;
}
