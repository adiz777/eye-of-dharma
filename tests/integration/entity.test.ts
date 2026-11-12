// tests/integration/entity.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { createEntityRouter } from '../../server/routes/entity.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';
import * as ssrf from '../../server/security/ssrf.js';
import { runEntityLookup } from '../../server/connectors/entity_sources.js';

const ok = (body: unknown, statusCode = 200) =>
  ({ statusCode, statusText: '', headers: {}, data: JSON.stringify(body), url: '', pinnedIp: '1.1.1.1' }) as any;

describe('Public entity lookup', () => {
  let db: Database.Database;
  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    runMigrations(db);
    seedDatabase(db);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    db.close();
  });

  it('rejects requests without lawful-purpose confirmation or with unknown fields', async () => {
    const app = createApp(db);
    const base = { query_type: 'PERSON', target: 'Ada Lovelace', confirm_passive: true };
    expect((await request(app).post('/api/v1/investigate/entity').set('x-bypass-csrf', 'true').send(base)).status).toBe(400);
    const extra = { ...base, confirm_lawful_purpose: true, scrape_social: true };
    expect((await request(app).post('/api/v1/investigate/entity').set('x-bypass-csrf', 'true').send(extra)).status).toBe(400);
  });

  it('PERSON lookups only touch public-figure and sanctions sources (no social platforms)', async () => {
    const spy = vi.spyOn(ssrf, 'safeFetch').mockResolvedValue(ok({ search: [] }));
    const out = await runEntityLookup('PERSON', 'Ada Lovelace');
    expect(out.map((s) => s.sourceId).sort()).toEqual(['opensanctions', 'wikidata']);
    expect(out.find((s) => s.sourceId === 'opensanctions')!.status).toBe('unsupported'); // no key configured
    expect(spy.mock.calls.every((c) => /wikidata\.org/.test(String(c[0])))).toBe(true);
  });

  it('distinguishes found, not_found and error for username checks', async () => {
    vi.spyOn(ssrf, 'safeFetch').mockImplementation(async (url: string) => {
      if (url.includes('api.github.com')) return ok({ login: 'octo', html_url: 'https://github.com/octo', created_at: 'x', public_repos: 1 });
      if (url.includes('gitlab.com')) return ok([]);
      throw new Error('boom');
    });
    const out = await runEntityLookup('USERNAME', 'octo');
    const by = Object.fromEntries(out.map((s) => [s.sourceId, s.status]));
    expect(by).toEqual({ github: 'found', gitlab: 'not_found', hackernews: 'error' });
  });

  it('rejects malformed usernames before any network call', async () => {
    const spy = vi.spyOn(ssrf, 'safeFetch');
    await expect(runEntityLookup('USERNAME', '../etc/passwd')).rejects.toThrow();
    expect(spy).not.toHaveBeenCalled();
  });

  it('audits the query and stores evidence once per identical result when a case is given', async () => {
    const lookup = vi.fn().mockResolvedValue([
      { sourceId: 'wikidata', sourceName: 'Wikidata', status: 'found', records: [{ label: 'X' }], retrievedAt: 't' }
    ]);
    const app = express().use(express.json()).use('/api/v1', createEntityRouter(db, lookup));
    const caseId = (db.prepare('SELECT id FROM cases LIMIT 1').get() as { id: string }).id;
    const body = { query_type: 'ORGANIZATION', target: 'Acme Corp', confirm_passive: true, confirm_lawful_purpose: true, case_id: caseId };

    const a = await request(app).post('/api/v1/investigate/entity').send(body);
    const b = await request(app).post('/api/v1/investigate/entity').send(body);
    expect(a.body.found).toBe(true);
    expect(a.body.evidence_id).toBeTruthy();
    expect(b.body.evidence_id).toBe(a.body.evidence_id);
    const audits = db.prepare("SELECT count(*) c FROM audit_events WHERE action = 'PUBLIC_ENTITY_QUERY'").get() as { c: number };
    expect(audits.c).toBe(2);
  });
});
