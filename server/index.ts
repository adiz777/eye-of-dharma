// server/index.ts
// Production entrypoint for EYE OF DHARMA Operations Platform

import { getDatabase } from './db/connection.js';
import { runMigrations } from './db/migrate.js';
import { seedDatabase } from './db/seed.js';
import { createApp } from './app.js';
import { createDefaultConnectorManager } from './connectors/manager.js';

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1'; // no auth yet: bind to loopback by default

async function bootstrap() {
  try {
    console.log('[EYE OF DHARMA] Initializing relational database...');
    const db = getDatabase();

    // Run migrations
    runMigrations(db);

    // Auto-seed synthetic scenarios if in development or if table is empty
    const shouldSeed = process.env.EOD_AUTO_SEED !== 'false';
    if (shouldSeed) {
      seedDatabase(db);
    }

    const connectorManager = createDefaultConnectorManager(db);
    const app = createApp(db, { connectorManager });

    // Background ingestion: poll public feeds on a modest interval (respects upstream rate limits).
    const pollMs = parseInt(process.env.EOD_FEED_POLL_MS || '600000', 10);
    if (process.env.EOD_DISABLE_POLLING !== 'true') {
      for (const id of ['usgs_earthquakes', 'nasa_eonet', 'cisa_intel', 'rss_feed']) {
        connectorManager.refreshConnector(id).catch((err) => console.error(`[EYE OF DHARMA] Initial ingest failed for ${id}:`, err));
        connectorManager.startPolling(id, pollMs);
      }
    }

    const server = app.listen(PORT, HOST, () => {
      console.log(`[EYE OF DHARMA] Operations Center Backend listening on http://${HOST}:${PORT}`);
      console.log(`[EYE OF DHARMA] Health check available at http://localhost:${PORT}/api/v1/health`);
    });

    const shutdown = () => {
      console.log('[EYE OF DHARMA] Gracefully shutting down...');
      server.close(() => {
        db.close();
        console.log('[EYE OF DHARMA] Server terminated cleanly.');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (err) {
    console.error('[EYE OF DHARMA] Bootstrap failed:', err);
    process.exit(1);
  }
}

bootstrap();
