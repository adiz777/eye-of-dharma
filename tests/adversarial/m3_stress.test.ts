// tests/adversarial/m3_stress.test.ts
// Empirical Challenger Stress Test Suite for Milestone M3
// Tests:
// 1. Terminal Command Injection & Allowlist Stress Testing (Client & Backend)
// 2. Buffer Overflow & Metacharacter Payload Matrix
// 3. Static Serving, SPA Fallback & Directory Traversal Security

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';
import { TerminalCommandSchema } from '../../server/security/validation.js';
// @ts-expect-error JS module without declaration file
import { parseTerminalCommand, SHELL_METACHARACTER_REGEX } from '../../public/js/components/terminal_console.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, '..', '..', 'public');

describe('M3 Adversarial Challenge: Terminal Command Injection Stress Test', () => {
  const maliciousShellPayloads = [
    { name: 'Semicolon command chaining', input: 'cases list; rm -rf /' },
    { name: 'Logical AND chaining', input: 'status && whoami' },
    { name: 'Pipeline execution', input: 'help | grep secret' },
    { name: 'Command substitution subshell $()', input: '$(id)' },
    { name: 'Command substitution backticks', input: '`cat /etc/passwd`' },
    { name: 'Redirection output >', input: 'cases list > dump.txt' },
    { name: 'Redirection input <', input: 'status < /etc/shadow' },
    { name: 'Environment variable expansion', input: '$HOME' },
    { name: 'Logical OR chaining', input: 'status || reboot' },
    { name: 'Background execution &', input: 'cases list &' },
    { name: 'Subshell parentheses', input: '(echo hacked)' },
    { name: 'Shell brace expansion', input: '{echo,hacked}' },
    { name: 'Escape character backslash', input: 'cases\\ list' },
    { name: 'History expansion exclamation', input: '!rm' }
  ];

  describe('1.1 Client-side parseTerminalCommand Security Defense', () => {
    for (const { name, input } of maliciousShellPayloads) {
      it(`blocks ${name}: "${input}" before dispatch`, () => {
        const res = parseTerminalCommand(input);
        expect(res.valid, `Expected "${input}" to be rejected`).toBe(false);
        expect(res.error).toBeDefined();
        // Check that either illegal characters or not recognized error is returned
        expect(res.error).toMatch(/Illegal characters detected|Command.*not recognized|exceeds maximum length/);
      });
    }

    it('rejects empty and whitespace-only commands', () => {
      expect(parseTerminalCommand('').valid).toBe(false);
      expect(parseTerminalCommand('   ').valid).toBe(false);
    });

    it('rejects non-string inputs', () => {
      expect(parseTerminalCommand(123 as any).valid).toBe(false);
      expect(parseTerminalCommand(null as any).valid).toBe(false);
      expect(parseTerminalCommand(undefined as any).valid).toBe(false);
    });

    it('rejects client buffer overflow (>256 characters)', () => {
      const huge = 'status ' + 'A'.repeat(251);
      const res = parseTerminalCommand(huge);
      expect(res.valid).toBe(false);
      expect(res.error).toContain('exceeds maximum length of 256 characters');
    });

    it('strictly permits allowlisted commands only', () => {
      const allowlisted = [
        'help',
        'status',
        'sources',
        'cases list',
        'case show case-1234',
        'threats recent',
        'system health',
        'clear'
      ];
      for (const cmd of allowlisted) {
        const res = parseTerminalCommand(cmd);
        expect(res.valid, `Expected "${cmd}" to be valid`).toBe(true);
      }
    });

    it('rejects unauthorized or arbitrary CLI binaries', () => {
      const unauthorized = [
        'ls', 'dir', 'rm', 'cat', 'curl', 'wget', 'sudo', 'powershell',
        'cmd.exe', 'bash', 'node', 'python', 'sh', 'chmod', 'chown', 'netstat'
      ];
      for (const cmd of unauthorized) {
        const res = parseTerminalCommand(cmd);
        expect(res.valid, `Expected "${cmd}" to be blocked`).toBe(false);
        expect(res.error).toContain('not recognized or not permitted');
      }
    });
  });

  describe('1.2 Backend Terminal Router Defense & Boundary Behavior', () => {
    let db: Database.Database;
    let app: import('express').Express;

    beforeEach(() => {
      process.env.NODE_ENV = 'test';
      db = new Database(':memory:');
      runMigrations(db);
      seedDatabase(db);
      app = createApp(db, { publicDir });
    });

    afterEach(() => {
      db.close();
    });

    it('rejects unauthenticated requests without CSRF protection (HTTP 403)', async () => {
      const res = await request(app)
        .post('/api/v1/terminal/exec')
        .send({ command: 'help' });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('CSRF_TOKEN_MISSING');
    });

    it('rejects backend buffer overflow (>200 characters) via Zod TerminalCommandSchema', async () => {
      const hugeInput = 'help ' + 'X'.repeat(200); // 205 chars
      const zodCheck = TerminalCommandSchema.safeParse({ command: hugeInput });
      expect(zodCheck.success).toBe(false);

      const res = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: hugeInput });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('rejects missing or empty command body with HTTP 400', async () => {
      const res = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: '' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('rejects extra unknown body properties (.strict()) with HTTP 400', async () => {
      const res = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'help', extra: 'malicious' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('backend safely handles all shell metacharacter payloads without executing host commands', async () => {
      for (const { name, input } of maliciousShellPayloads) {
        const res = await request(app)
          .post('/api/v1/terminal/exec')
          .set('x-bypass-csrf', 'true')
          .send({ command: input });

        expect(res.status).toBe(200);
        // The backend should NEVER return shell execution output
        expect(res.body.output).not.toContain('root:');
        expect(res.body.output).not.toContain('uid=');
        expect(res.body.output).not.toContain('/home/');
      }
    });

    it('backend terminal case show is immune to SQL injection attacks via parameter binding', async () => {
      const sqlInjectionPayloads = [
        "case show ' OR '1'='1",
        "case show 1; DROP TABLE cases;--",
        "case show ' UNION SELECT null, null, null, null, null, null, null, null, null--",
        'case show " OR ""="',
        "case show ' OR 1=1 /*"
      ];

      for (const payload of sqlInjectionPayloads) {
        const res = await request(app)
          .post('/api/v1/terminal/exec')
          .set('x-bypass-csrf', 'true')
          .send({ command: payload });

        expect(res.status).toBe(200);
        // It must not leak SQL errors or other records
        expect(res.body.output).toMatch(/not found|Usage: case show/);

        // Verify cases table was NOT dropped or tampered with
        const count = (db.prepare('SELECT COUNT(*) as cnt FROM cases').get() as { cnt: number }).cnt;
        expect(count).toBeGreaterThan(0);
      }
    });

    it('backend correctly routes valid allowlisted commands', async () => {
      const helpRes = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'help' });
      expect(helpRes.status).toBe(200);
      expect(helpRes.body.output).toContain('EYE OF DHARMA ALLOWLISTED TERMINAL CONSOLE');

      const statusRes = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'status' });
      expect(statusRes.status).toBe(200);
      expect(statusRes.body.output).toContain('[EOD OPERATIONAL STATUS]');

      const sourcesRes = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'sources' });
      expect(sourcesRes.status).toBe(200);
      expect(sourcesRes.body.output).toContain('USGS Earthquakes API');

      const casesRes = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'cases list' });
      expect(casesRes.status).toBe(200);
      expect(casesRes.body.output).toContain('[RECENT CASES');
    });

    it('backend rejects unauthorized command verbs as not recognized', async () => {
      const res = await request(app)
        .post('/api/v1/terminal/exec')
        .set('x-bypass-csrf', 'true')
        .send({ command: 'rm -rf /' });

      expect(res.status).toBe(200);
      expect(res.body.output).toContain("Command not recognized: 'rm -rf /'");
    });
  });
});

describe('M3 Adversarial Challenge: Static Serving & SPA Fallback Security Stress Test', () => {
  let db: Database.Database;
  let app: import('express').Express;

  beforeEach(() => {
    db = new Database(':memory:');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db, { publicDir });
  });

  afterEach(() => {
    db.close();
  });

  describe('2.1 Directory Traversal Security', () => {
    const traversalPayloads = [
      '/../../etc/passwd',
      '/..%2f..%2fetc/passwd',
      '/..%252f..%252fetc/passwd',
      '/....//....//etc/passwd',
      '/../../server/config.ts',
      '/..\\..\\server\\config.ts',
      '/../package.json',
      '/..%2fpackage.json',
      '/..%5cpackage.json',
      '/%2e%2e/%2e%2e/etc/passwd'
    ];

    for (const payload of traversalPayloads) {
      it(`prevents directory traversal for payload: "${payload}"`, async () => {
        const res = await request(app).get(payload);

        // Security assertion: it must NEVER return sensitive backend code or system files
        expect(res.text).not.toContain('better-sqlite3');
        expect(res.text).not.toContain('root:x:0:0:');
        expect(res.text).not.toContain('"dependencies"');

        // It should either return 404 (with ROUTE_NOT_FOUND or standard 404) or SPA fallback HTML
        if (res.status === 200) {
          expect(res.headers['content-type']).toMatch(/html/);
          expect(res.text).toContain('EYE OF DHARMA');
        } else {
          expect(res.status).toBe(404);
        }
      });
    }
  });

  describe('2.2 Unhandled API Routes JSON 404 Integrity', () => {
    const unhandledApiRoutes = [
      '/api/v1/nonexistent',
      '/api/v1/cases/unknown/subroute',
      '/api/v1/admin/secret',
      '/api/v1/',
      '/api/nonexistent',
      '/api/v1/threats/123/delete',
      '/api/v1/feeds/nonexistent/records'
    ];

    for (const route of unhandledApiRoutes) {
      it(`returns JSON 404 (ROUTE_NOT_FOUND) for "${route}" and never HTML`, async () => {
        const res = await request(app).get(route);
        expect(res.status).toBe(404);
        expect(res.headers['content-type']).toMatch(/json/);
        expect(res.body.success).toBe(false);
        expect(res.body.error).toBeDefined();
        expect(res.body.error.code).toBe('ROUTE_NOT_FOUND');
        expect(res.text).not.toContain('<!DOCTYPE html>');
      });
    }
  });

  describe('2.3 Missing Static File Extensions 404 Integrity', () => {
    const missingAssetRoutes = [
      '/missing.js',
      '/missing.css',
      '/missing.png',
      '/missing.jpg',
      '/missing.svg',
      '/assets/missing.ico',
      '/js/components/nonexistent.js',
      '/css/nonexistent.css',
      '/vendor/nonexistent.woff2'
    ];

    for (const assetRoute of missingAssetRoutes) {
      it(`returns 404 JSON for missing asset "${assetRoute}" and never index.html`, async () => {
        const res = await request(app).get(assetRoute);
        expect(res.status).toBe(404);
        expect(res.headers['content-type']).toMatch(/json/);
        expect(res.body.success).toBe(false);
        expect(res.body.error.code).toBe('ROUTE_NOT_FOUND');
        expect(res.text).not.toContain('<!DOCTYPE html>');
      });
    }
  });

  describe('2.4 Deep Client SPA Routes Fallback Integrity', () => {
    const spaRoutes = [
      '/command-center',
      '/global-monitor',
      '/live-intel',
      '/cyber-threats',
      '/investigations',
      '/cases',
      '/cases/case-123',
      '/cases/case-00000000-0000-0000-0000-000000000001/evidence',
      '/entity-graph',
      '/timeline',
      '/ai-ops',
      '/watchlists',
      '/reports',
      '/data-sources',
      '/audit-logs',
      '/settings',
      '/system-health',
      '/deep/nested/view/path'
    ];

    for (const spaRoute of spaRoutes) {
      it(`returns 200 OK with index.html for SPA route "${spaRoute}"`, async () => {
        const res = await request(app).get(spaRoute);
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toMatch(/html/);
        expect(res.text).toContain('<!DOCTYPE html>');
        expect(res.text).toContain('EYE OF DHARMA');
        expect(res.text).toContain('role="banner"');
      });
    }
  });

  describe('2.5 Missing Static Files with Query Parameters Integrity', () => {
    const assetsWithQueries = [
      '/missing.js?v=1.0.0',
      '/missing.css?cache=false',
      '/images/missing.png?width=200&format=webp',
      '/bundle.min.js?hash=abcdef123456'
    ];

    for (const url of assetsWithQueries) {
      it(`returns 404 JSON for missing asset with query params: "${url}"`, async () => {
        const res = await request(app).get(url);
        expect(res.status).toBe(404);
        expect(res.headers['content-type']).toMatch(/json/);
        expect(res.body.success).toBe(false);
        expect(res.body.error.code).toBe('ROUTE_NOT_FOUND');
        expect(res.text).not.toContain('<!DOCTYPE html>');
      });
    }
  });

  describe('2.6 HTTP Method Tampering on Client SPA Routes', () => {
    const nonGetMethods = ['post', 'put', 'patch', 'delete'] as const;
    const clientPaths = ['/command-center', '/', '/cases/case-123', '/entity-graph'];

    for (const method of nonGetMethods) {
      for (const route of clientPaths) {
        it(`${method.toUpperCase()} "${route}" does NOT return index.html (returns 403 CSRF or 404 JSON)`, async () => {
          const res = await request(app)[method](route).set('x-bypass-csrf', 'true');
          expect(res.status).toBe(404);
          expect(res.headers['content-type']).toMatch(/json/);
          expect(res.body.success).toBe(false);
          expect(res.body.error.code).toBe('ROUTE_NOT_FOUND');
          expect(res.text).not.toContain('<!DOCTYPE html>');
        });
      }
    }
  });

  describe('2.7 Security Headers on Static and SPA Responses', () => {
    it('attaches defense-in-depth headers on index.html', async () => {
      const res = await request(app).get('/');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('DENY');
      expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    });

    it('attaches defense-in-depth headers on SPA fallback routes', async () => {
      const res = await request(app).get('/command-center');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('DENY');
    });
  });
});

