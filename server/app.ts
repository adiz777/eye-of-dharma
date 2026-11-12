// server/app.ts
// Express Application Assembly for EYE OF DHARMA Operations Platform

import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import type Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const defaultPublicDir = path.resolve(__dirname, '..', 'public');

import { csrfProtection } from './security/csrf.js';
import { createHealthRouter } from './routes/health.js';
import { createCasesRouter } from './routes/cases.js';
import { createEvidenceRouter } from './routes/evidence.js';
import { createEntitiesRouter } from './routes/entities.js';
import { createRelationshipsRouter } from './routes/relationships.js';
import { createThreatsRouter } from './routes/threats.js';
import { createFeedsRouter } from './routes/feeds.js';
import { createWatchlistsRouter } from './routes/watchlists.js';
import { createAuditRouter } from './routes/audit.js';
import { createTerminalRouter } from './routes/terminal.js';
import { createFootprintRouter } from './routes/footprint.js';
import { createAgentsRouter } from './routes/agents.js';
import type { ConnectorManager } from './connectors/manager.js';

export function createApp(db: Database.Database, options?: { publicDir?: string; connectorManager?: ConnectorManager }): Express {
  const app = express();
  const publicDir = options?.publicDir || process.env.PUBLIC_DIR || defaultPublicDir;

  // Security & utility middlewares
  app.use(cors({ origin: true, credentials: true }));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  app.use(cookieParser());
  app.use(csrfProtection);

  // Security response headers
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // CSRF token retrieval endpoint
  app.get(['/api/v1/auth/csrf', '/api/auth/csrf'], (req, res) => {
    const token = req.cookies?.['eod_csrf_token'] || '';
    res.json({ success: true, csrfToken: token });
  });

  // Initialize routers
  const healthRouter = createHealthRouter(db);
  const casesRouter = createCasesRouter(db);
  const evidenceRouter = createEvidenceRouter(db);
  const entitiesRouter = createEntitiesRouter(db);
  const relationshipsRouter = createRelationshipsRouter(db);
  const threatsRouter = createThreatsRouter(db);
  const feedsRouter = createFeedsRouter(db, options?.connectorManager);
  const watchlistsRouter = createWatchlistsRouter(db);
  const auditRouter = createAuditRouter(db);
  const terminalRouter = createTerminalRouter(db);
  const footprintRouter = createFootprintRouter(db);
  const agentsRouter = createAgentsRouter(db);

  // Mount under both /api/v1 and /api for full compatibility
  const subRouters = [
    healthRouter,
    casesRouter,
    evidenceRouter,
    entitiesRouter,
    relationshipsRouter,
    threatsRouter,
    feedsRouter,
    watchlistsRouter,
    auditRouter,
    terminalRouter,
    footprintRouter,
    agentsRouter
  ];

  for (const router of subRouters) {
    app.use('/api/v1', router);
    app.use('/api', router);
  }

  // Serve static assets from public/ directory
  app.use(express.static(publicDir, {
    index: false,
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0
  }));

  // SPA fallback route: serve public/index.html for client-side GET routes
  app.get('*', (req: Request, res: Response, next: NextFunction) => {
    // 1. Preserve API endpoints: do not intercept /api or /api/v1
    if (req.path.startsWith('/api/') || req.path === '/api' || req.path.startsWith('/api/v1/') || req.path === '/api/v1') {
      return next();
    }

    // 2. Reject missing static assets with extensions to prevent MIME type mismatch
    if (path.extname(req.path) && path.extname(req.path) !== '.html') {
      return next();
    }

    const indexPath = path.join(publicDir, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      return res.sendFile(indexPath);
    }

    next();
  });

  // 404 Handler
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      error: {
        code: 'ROUTE_NOT_FOUND',
        message: `Route '${req.method} ${req.originalUrl}' not found`
      }
    });
  });

  // Centralized Error Handler
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[EOD Server Error]', err);

    const errorObj = err as { code?: string; message?: string; status?: number; statusCode?: number };
    const statusCode = errorObj.status || errorObj.statusCode || 500;
    const code = errorObj.code || 'INTERNAL_SERVER_ERROR';
    const message = errorObj.message || 'An unexpected internal error occurred';

    res.status(statusCode).json({
      success: false,
      error: {
        code,
        message
      }
    });
  });

  return app;
}
