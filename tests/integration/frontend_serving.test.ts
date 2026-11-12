// tests/integration/frontend_serving.test.ts
// Integration tests for server/app.ts static asset serving & SPA routing fallback

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';

describe('Frontend Static Asset Serving & SPA Routing', () => {
  let db: Database.Database;
  let app: import('express').Express;

  beforeEach(() => {
    db = new Database(':memory:');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('GET / should serve index.html with text/html content type', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
    expect(res.text).toContain('EYE OF DHARMA');
  });

  it('GET /css/style.css should serve CSS with text/css content type', async () => {
    const res = await request(app).get('/css/style.css');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/css/);
    expect(res.text).toContain('--bg-base');
  });

  it('GET /js/components/command_palette.js should serve JavaScript', async () => {
    const res = await request(app).get('/js/components/command_palette.js');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/javascript/);
  });

  it('GET non-API client routes should fall back to index.html with 200 OK', async () => {
    const clientRoutes = [
      '/command-center',
      '/global-monitor',
      '/live-intel',
      '/cyber-threats',
      '/cases',
      '/cases/case-00000000-0000-0000-0000-000000000001',
      '/entity-graph',
      '/timeline',
      '/ai-ops',
      '/watchlists',
      '/reports',
      '/data-sources',
      '/audit-logs',
      '/settings',
      '/system-health'
    ];

    for (const route of clientRoutes) {
      const res = await request(app).get(route);
      expect(res.status, `Expected route '${route}' to return 200 OK`).toBe(200);
      expect(res.headers['content-type']).toMatch(/html/);
      expect(res.text).toContain('EYE OF DHARMA');
    }
  });

  it('GET /api/v1/* routes should preserve JSON responses and NOT fall back to index.html', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/json/);
    expect(res.body.status).toBe('UP');
  });

  it('GET unknown /api/v1/* routes should return 404 JSON error instead of index.html', async () => {
    const res = await request(app).get('/api/v1/non_existent_route');
    expect(res.status).toBe(404);
    expect(res.headers['content-type']).toMatch(/json/);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('ROUTE_NOT_FOUND');
  });

  it('GET unknown static asset with extension should return 404 JSON error instead of index.html', async () => {
    const res = await request(app).get('/assets/missing_file.png');
    expect(res.status).toBe(404);
    expect(res.headers['content-type']).toMatch(/json/);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('ROUTE_NOT_FOUND');
  });

  it('should include security response headers on static responses', async () => {
    const res = await request(app).get('/');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });
});
