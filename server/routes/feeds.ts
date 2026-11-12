// server/routes/feeds.ts
// Feed records cache and ingestion endpoints

import { Router } from 'express';
import type Database from 'better-sqlite3';
import type { FeedRecord } from '../db/schema.js';
import { ConnectorManager, createDefaultConnectorManager } from '../connectors/manager.js';

export function createFeedsRouter(db: Database.Database, manager?: ConnectorManager): Router {
  const router = Router();
  const connectorMgr = manager || createDefaultConnectorManager(db);

  // List feed records
  router.get('/feeds', (req, res) => {
    const { category, feed_name, limit = '50', offset = '0' } = req.query;
    const l = Math.min(Math.max(parseInt(String(limit), 10) || 50, 1), 100);
    const o = Math.max(parseInt(String(offset), 10) || 0, 0);

    // Synthetic demo rows must never surface as live intelligence.
    const conditions: string[] = ['is_synthetic = 0'];
    const params: (string | number)[] = [];

    if (category && typeof category === 'string') {
      conditions.push('category = ?');
      params.push(category);
    }
    if (feed_name && typeof feed_name === 'string') {
      conditions.push('feed_name = ?');
      params.push(feed_name);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as total FROM feed_records ${whereClause}`).get(...params) as { total: number };
    const items = db.prepare(`SELECT * FROM feed_records ${whereClause} ORDER BY published_at DESC LIMIT ? OFFSET ?`).all(...params, l, o) as FeedRecord[];

    const parsedItems = items.map((f) => ({
      ...f,
      payload: typeof f.payload === 'string' ? JSON.parse(f.payload || '{}') : f.payload
    }));

    res.json({
      success: true,
      items: parsedItems,
      total: countRow.total,
      limit: l,
      offset: o
    });
  });

  // Query connector health status
  router.get('/feeds/health', async (_req, res) => {
    try {
      const health = await connectorMgr.healthAll();
      res.json({
        success: true,
        connectors: health
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({
        success: false,
        error: { code: 'HEALTH_CHECK_FAILED', message: msg }
      });
    }
  });

  // Refresh feeds
  router.post('/feeds/refresh', async (req, res) => {
    // Only periodic feed connectors; crt.sh / DNS-RDAP need a query target and run via /investigate/footprint.
    const feedNames = req.body?.feed_names || ['usgs_earthquakes', 'nasa_eonet', 'cisa_intel', 'rss_feed'];

    try {
      const summary = await connectorMgr.refreshAll(feedNames);
      res.json({
        success: summary.errors.length === 0,
        refreshed: summary.refreshed,
        count: summary.count,
        totalFetched: summary.totalFetched,
        insertedEvidence: summary.totalInsertedEvidence,
        updatedFeeds: summary.totalUpdatedFeeds,
        skippedDuplicates: summary.totalSkippedDuplicates,
        errors: summary.errors
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({
        success: false,
        error: { code: 'FEED_REFRESH_FAILED', message: msg }
      });
    }
  });

  return router;
}
