// tests/integration/connectors_adversarial.test.ts
// Adversarial Stress & Resilience Verification Suite for Milestone M2 Connectors
// Executed by Connectors Resilience Adversarial Challenger

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import {
  TokenBucketLimiter,
  TokenBucket,
  RateLimitExceededError,
  CircuitBreaker,
  CircuitBreakerOpenError,
  computeCanonicalFingerprint,
  type NormalizedEvidenceItem
} from '../../server/connectors/base.js';
import { ConnectorManager } from '../../server/connectors/manager.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase, computeSha256 } from '../../server/db/seed.js';

// ---------------------------------------------------------------------------
// SUITE 1: TokenBucketLimiter Adversarial & Stress Tests
// ---------------------------------------------------------------------------
describe('Adversarial Stress Suite 1: TokenBucketLimiter', () => {
  it('should accurately deplete under rapid burst without over-allocating tokens', () => {
    const burstCapacity = 100;
    const refillRate = 1; // 1 token per second
    const limiter = new TokenBucketLimiter(burstCapacity, refillRate);

    let consumedCount = 0;
    for (let i = 0; i < burstCapacity; i++) {
      if (limiter.tryConsume(1)) {
        consumedCount++;
      }
    }

    expect(consumedCount).toBe(burstCapacity);
    expect(limiter.availableTokens).toBe(0);

    // Burst exhausted: immediate subsequent consumption must fail
    expect(limiter.tryConsume(1)).toBe(false);
    expect(limiter.tryConsume(0.1)).toBe(false);
  });

  it('should strictly respect multi-token costs during burst depletion', () => {
    const capacity = 50;
    const limiter = new TokenBucketLimiter(capacity, 5);

    // Consume 10 chunks of 5 tokens
    for (let i = 0; i < 10; i++) {
      expect(limiter.tryConsume(5)).toBe(true);
    }

    // Now empty
    expect(limiter.tryConsume(5)).toBe(false);
    expect(limiter.tryConsume(1)).toBe(false);
  });

  it('should refill tokens incrementally over simulated time and clamp strictly at capacity', () => {
    let simulatedTime = 1_000_000;
    const capacity = 20;
    const refillRate = 4; // 4 tokens per second (1 token per 250ms)
    const limiter = new TokenBucketLimiter(capacity, refillRate, () => simulatedTime);

    // Completely drain bucket
    expect(limiter.tryConsume(capacity)).toBe(true);
    expect(limiter.tryConsume(1)).toBe(false);

    // Step 1: Advance 250ms -> should refill exactly 1 token
    simulatedTime += 250;
    expect(limiter.tryConsume(1)).toBe(true);
    expect(limiter.tryConsume(1)).toBe(false);

    // Step 2: Advance 500ms -> should refill 2 tokens
    simulatedTime += 500;
    expect(limiter.tryConsume(2)).toBe(true);
    expect(limiter.tryConsume(1)).toBe(false);

    // Step 3: Advance 100,000ms (100 seconds) -> should cap at capacity (20), not 400
    simulatedTime += 100_000;
    expect(limiter.availableTokens).toBe(20);
    expect(limiter.tryConsume(20)).toBe(true);
    expect(limiter.tryConsume(1)).toBe(false);
  });

  it('should handle fractional token consumption and precise decimal math', () => {
    let simulatedTime = 500_000;
    const capacity = 10;
    const refillRate = 2.5; // 2.5 tokens/sec
    const limiter = new TokenBucketLimiter(capacity, refillRate, () => simulatedTime);

    // Consume 9.5 tokens
    expect(limiter.tryConsume(9.5)).toBe(true);
    expect(limiter.availableTokens).toBeCloseTo(0.5, 1);

    // Attempting to consume 1 token should fail
    expect(limiter.tryConsume(1)).toBe(false);
    // Consuming 0.5 tokens should succeed
    expect(limiter.tryConsume(0.5)).toBe(true);
  });

  it('should throw RateLimitExceededError immediately if calculated waitMs exceeds maxWaitMs', async () => {
    const limiter = new TokenBucket(2, 0.5); // 0.5 tokens/sec = 2000ms per token
    expect(limiter.tryConsume(2)).toBe(true);

    // Now empty. Requesting 1 token requires 2000ms wait.
    // If maxWaitMs is 1000ms, it must throw RateLimitExceededError immediately.
    const start = performance.now();
    await expect(limiter.acquire(1, 1000, 'adversarial-connector')).rejects.toThrow(RateLimitExceededError);
    const elapsed = performance.now() - start;

    // Must reject fast without waiting 1000ms or 2000ms
    expect(elapsed).toBeLessThan(100);
  });

  it('should wait and successfully acquire tokens when waitMs is within maxWaitMs', async () => {
    const limiter = new TokenBucket(1, 20); // 20 tokens/sec = 50ms per token
    expect(limiter.tryConsume(1)).toBe(true);

    // Needs 1 token -> wait is ~50ms. Max wait is 500ms.
    const start = performance.now();
    await limiter.acquire(1, 500, 'fast-connector');
    const elapsed = performance.now() - start;

    expect(elapsed).toBeGreaterThanOrEqual(30);
    expect(elapsed).toBeLessThan(400);
  });

  it('should handle rapid concurrent acquire calls without race condition corrupted balances', async () => {
    const limiter = new TokenBucket(10, 50); // fast refill for test speed

    // Fire 10 concurrent acquire calls
    const tasks = Array.from({ length: 10 }, (_, i) =>
      limiter.acquire(1, 2000, `client-${i}`)
    );

    await expect(Promise.all(tasks)).resolves.toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// SUITE 2: CircuitBreaker Adversarial State Machine Stress Tests
// ---------------------------------------------------------------------------
describe('Adversarial Stress Suite 2: CircuitBreaker', () => {
  it('should maintain CLOSED state until threshold consecutive failures occur', async () => {
    const threshold = 5;
    const cb = new CircuitBreaker(threshold, 500);

    const failOp = async () => {
      throw new Error('EOD_UPSTREAM_UNAVAILABLE_503');
    };

    // First 4 failures must keep state as CLOSED
    for (let i = 1; i < threshold; i++) {
      await expect(cb.execute(failOp, 'test-connector')).rejects.toThrow('EOD_UPSTREAM_UNAVAILABLE_503');
      expect(cb.getState()).toBe('CLOSED');
      expect(cb.failureCount).toBe(i);
      expect(cb.isOpen()).toBe(false);
    }

    // 5th failure must immediately transition state to OPEN
    await expect(cb.execute(failOp, 'test-connector')).rejects.toThrow('EOD_UPSTREAM_UNAVAILABLE_503');
    expect(cb.getState()).toBe('OPEN');
    expect(cb.failureCount).toBe(5);
    expect(cb.isOpen()).toBe(true);
  });

  it('should reset failure count when a success occurs before reaching threshold', async () => {
    const cb = new CircuitBreaker(5, 500);

    // 4 failures
    for (let i = 0; i < 4; i++) {
      await expect(cb.execute(async () => { throw new Error('Temp Fail'); })).rejects.toThrow();
    }
    expect(cb.failureCount).toBe(4);
    expect(cb.getState()).toBe('CLOSED');

    // 1 success resets counter to 0
    const res = await cb.execute(async () => 'ALL_GOOD');
    expect(res).toBe('ALL_GOOD');
    expect(cb.failureCount).toBe(0);
    expect(cb.getState()).toBe('CLOSED');
  });

  it('should fail fast in OPEN state with CircuitBreakerOpenError and ZERO target executions', async () => {
    const cb = new CircuitBreaker(5, 1000);
    // Force OPEN state
    for (let i = 0; i < 5; i++) {
      await expect(cb.execute(async () => { throw new Error('Down'); })).rejects.toThrow();
    }
    expect(cb.getState()).toBe('OPEN');

    const networkMock = vi.fn(async () => 'SHOULD_NEVER_RUN');

    // Execute 50 rapid calls under OPEN state
    const burstPromises = Array.from({ length: 50 }, () =>
      cb.execute(networkMock, 'cisa-intel').catch((err) => err)
    );

    const results = await Promise.all(burstPromises);

    // Every single call must have thrown CircuitBreakerOpenError
    for (const result of results) {
      expect(result).toBeInstanceOf(CircuitBreakerOpenError);
      expect((result as CircuitBreakerOpenError).connectorId).toBe('cisa-intel');
      expect((result as CircuitBreakerOpenError).cooldownRemainingMs).toBeGreaterThan(0);
    }

    // Crucial adversarial verification: zero network calls made
    expect(networkMock).not.toHaveBeenCalled();
  });

  it('should transition to HALF_OPEN after cooldownMs and recover to CLOSED upon success', async () => {
    const cooldownMs = 60;
    const cb = new CircuitBreaker(3, cooldownMs);

    for (let i = 0; i < 3; i++) {
      await expect(cb.execute(async () => { throw new Error('Trip'); })).rejects.toThrow();
    }
    expect(cb.getState()).toBe('OPEN');

    // Wait until cooldown period expires
    await new Promise((r) => setTimeout(r, cooldownMs + 20));

    // Must now report HALF_OPEN
    expect(cb.getState()).toBe('HALF_OPEN');
    expect(cb.isOpen()).toBe(false); // trial call allowed

    // Successful trial call
    const trialMock = vi.fn(async () => 'RECOVERED_TELEMETRY');
    const result = await cb.execute(trialMock, 'usgs-feed');

    expect(result).toBe('RECOVERED_TELEMETRY');
    expect(trialMock).toHaveBeenCalledTimes(1);
    expect(cb.getState()).toBe('CLOSED');
    expect(cb.failureCount).toBe(0);
  });

  it('should immediately re-trip to OPEN if trial call fails in HALF_OPEN state', async () => {
    const cooldownMs = 50;
    const cb = new CircuitBreaker(2, cooldownMs);

    // Trip to OPEN
    await expect(cb.execute(async () => { throw new Error('F1'); })).rejects.toThrow();
    await expect(cb.execute(async () => { throw new Error('F2'); })).rejects.toThrow();
    expect(cb.getState()).toBe('OPEN');

    // Wait for cooldown
    await new Promise((r) => setTimeout(r, cooldownMs + 10));
    expect(cb.getState()).toBe('HALF_OPEN');

    // Trial call fails
    await expect(cb.execute(async () => { throw new Error('Trial Failed'); })).rejects.toThrow('Trial Failed');

    // Must immediately re-trip to OPEN
    expect(cb.getState()).toBe('OPEN');
    expect(cb.isOpen()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// SUITE 3: ConnectorManager Persistence & Immutability Trigger Stress Tests
// ---------------------------------------------------------------------------
describe('Adversarial Stress Suite 3: Persistence & Immutability Triggers', () => {
  let db: Database.Database;
  let manager: ConnectorManager;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    db.pragma('recursive_triggers = ON');
    runMigrations(db);
    seedDatabase(db);
    manager = new ConnectorManager(db);
  });

  afterEach(() => {
    db.close();
  });

  function createMockItem(idSuffix: string, customPayload: Record<string, unknown> = {}): NormalizedEvidenceItem {
    const raw = { data: `adversarial-payload-${idSuffix}`, ...customPayload };
    const rawStr = JSON.stringify(raw);
    const hash = computeSha256(rawStr);

    return {
      id: `adv:item-${idSuffix}`,
      sourceConnectorId: 'cisa',
      sourceName: 'CISA KEV Catalog',
      sourceUrl: `https://cisa.gov/known-exploited-vulnerabilities?id=${idSuffix}`,
      sourceType: 'CISA_KEV',
      feedCategory: 'THREAT_INTEL',
      severity: 'CRITICAL',
      title: `Adversarial Threat Record ${idSuffix}`,
      summary: `Automated resilience test summary ${idSuffix}`,
      publishedAt: '2026-10-28T16:00:00Z',
      retrievedAt: '2026-10-28T16:05:00Z',
      verificationStatus: 'Source-reported',
      confidenceScore: 0.98,
      contentHash: hash,
      rawPayload: raw,
      coordinates: { lat: 38.8951, lon: -77.0364 }
    };
  }

  it('should verify SQLite engine-level triggers strictly block direct UPDATE, DELETE, and REPLACE on evidence_ledger', () => {
    const item = createMockItem('engine-trigger-test');
    const res = manager.persistItems([item]);
    expect(res.evidenceRecordsInserted).toBe(1);

    const evidId = `ev-${item.id.replace(/[:/]/g, '-')}`;

    // Test 1: Direct UPDATE must fail via trg_prevent_evidence_update
    expect(() => {
      db.prepare('UPDATE evidence_ledger SET source_title = ? WHERE id = ?').run('HACKED_TITLE', evidId);
    }).toThrow(/EVIDENCE_IMMUTABILITY_VIOLATION/);

    // Test 2: Direct DELETE must fail via trg_prevent_evidence_delete
    expect(() => {
      db.prepare('DELETE FROM evidence_ledger WHERE id = ?').run(evidId);
    }).toThrow(/EVIDENCE_IMMUTABILITY_VIOLATION/);

    // Test 3: Direct INSERT with duplicate ID must fail via trg_prevent_evidence_replace
    expect(() => {
      db.prepare(`
        INSERT INTO evidence_ledger (
          id, source_url, source_type, source_title, content_fingerprint,
          raw_content, verification_status, confidence_score
        ) VALUES (?, 'https://attacker.site', 'CISA_KEV', 'Exploit', 'fakehash', 'payload', 'Observed', 0.5)
      `).run(evidId);
    }).toThrow(/EVIDENCE_IMMUTABILITY_VIOLATION/);
  });

  it('should safely skip rapid concurrent duplicate insertions without violating immutability triggers', () => {
    // Generate 50 items
    const items = Array.from({ length: 50 }, (_, i) => createMockItem(`batch-item-${i}`));

    // First ingestion: all 50 inserted
    const firstRun = manager.persistItems(items);
    expect(firstRun.evidenceRecordsInserted).toBe(50);
    expect(firstRun.evidenceDuplicatesSkipped).toBe(0);
    expect(firstRun.feedRecordsUpdated).toBe(50);

    // Second ingestion with identical 50 items: must safely skip all 50 without throwing
    const secondRun = manager.persistItems(items);
    expect(secondRun.evidenceRecordsInserted).toBe(0);
    expect(secondRun.evidenceDuplicatesSkipped).toBe(50);
    expect(secondRun.feedRecordsUpdated).toBe(50); // mutable feed cache refreshed

    // Third ingestion: interleaved batch of 25 duplicates + 25 brand new items
    const mixedBatch = [
      ...items.slice(0, 25),
      ...Array.from({ length: 25 }, (_, i) => createMockItem(`new-item-${i}`))
    ];

    const thirdRun = manager.persistItems(mixedBatch);
    expect(thirdRun.evidenceRecordsInserted).toBe(25);
    expect(thirdRun.evidenceDuplicatesSkipped).toBe(25);
    expect(thirdRun.feedRecordsUpdated).toBe(50);

    // Verify evidence_ledger row count equals exactly 75 items (50 original + 25 new)
    const countRow = db.prepare(
      "SELECT COUNT(*) as cnt FROM evidence_ledger WHERE id LIKE 'ev-adv-item-%'"
    ).get() as { cnt: number };
    expect(countRow.cnt).toBe(75);
  });

  it('should handle duplicate contentHash with different item id safely via check-before-insert', () => {
    const sharedPayload = { vulnerability: 'CVE-2026-99999', score: 10.0 };
    const sharedHash = computeSha256(JSON.stringify(sharedPayload));

    const itemA: NormalizedEvidenceItem = {
      id: 'srcA:cve-99999',
      sourceConnectorId: 'cisa',
      sourceName: 'Source A',
      sourceUrl: 'https://source-a.test',
      sourceType: 'CISA_KEV',
      feedCategory: 'THREAT_INTEL',
      severity: 'CRITICAL',
      title: 'Vuln 99999 A',
      summary: 'Summary A',
      publishedAt: '2026-10-28T10:00:00Z',
      retrievedAt: '2026-10-28T10:00:00Z',
      verificationStatus: 'Observed',
      confidenceScore: 1.0,
      contentHash: sharedHash,
      rawPayload: sharedPayload
    };

    const itemB: NormalizedEvidenceItem = {
      ...itemA,
      id: 'srcB:cve-99999',
      sourceName: 'Source B',
      sourceUrl: 'https://source-b.test',
      title: 'Vuln 99999 B'
    };

    // Item A inserted
    const resA = manager.persistItems([itemA]);
    expect(resA.evidenceRecordsInserted).toBe(1);
    expect(resA.evidenceDuplicatesSkipped).toBe(0);

    // Item B shares identical contentHash: should be detected as duplicate evidence and skipped
    const resB = manager.persistItems([itemB]);
    expect(resB.evidenceRecordsInserted).toBe(0);
    expect(resB.evidenceDuplicatesSkipped).toBe(1);
    // feed_records for Item B was still recorded
    expect(resB.feedRecordsUpdated).toBe(1);
  });

  it('should safely process massive 200-item batch containing duplicates and empty sets without error', () => {
    // Empty array edge case
    const emptyRes = manager.persistItems([]);
    expect(emptyRes.evidenceRecordsInserted).toBe(0);
    expect(emptyRes.evidenceDuplicatesSkipped).toBe(0);
    expect(emptyRes.feedRecordsUpdated).toBe(0);

    // 200 items with duplicate IDs embedded
    const batch: NormalizedEvidenceItem[] = [];
    for (let i = 0; i < 100; i++) {
      batch.push(createMockItem(`mass-item-${i}`));
      // Push duplicate immediately
      batch.push(createMockItem(`mass-item-${i}`));
    }
    expect(batch.length).toBe(200);

    const batchRes = manager.persistItems(batch);
    // In a 200-item array where each item appears twice:
    // First occurrence inserts (100), second occurrence finds existing and skips (100)
    expect(batchRes.evidenceRecordsInserted).toBe(100);
    expect(batchRes.evidenceDuplicatesSkipped).toBe(100);
    expect(batchRes.feedRecordsUpdated).toBe(200);
  });

  it('should maintain transaction rollback atomicity if a batch operation fails catastrophically', () => {
    // Count initial evidence records
    const initialEvidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM evidence_ledger').get() as any).cnt;
    const initialFeedCount = (db.prepare('SELECT COUNT(*) as cnt FROM feed_records').get() as any).cnt;

    // Craft a batch where item 2 has an invalid sourceType that violates CHECK constraint
    const validItem = createMockItem('valid-before-crash');
    const invalidItem = {
      ...createMockItem('invalid-check-violation'),
      sourceType: 'ILLEGAL_SOURCE_TYPE_THAT_VIOLATES_CHECK' as any
    };

    expect(() => {
      manager.persistItems([validItem, invalidItem]);
    }).toThrow();

    // Verify entire transaction rolled back: no partial inserts into evidence_ledger or feed_records
    const postEvidenceCount = (db.prepare('SELECT COUNT(*) as cnt FROM evidence_ledger').get() as any).cnt;
    const postFeedCount = (db.prepare('SELECT COUNT(*) as cnt FROM feed_records').get() as any).cnt;

    expect(postEvidenceCount).toBe(initialEvidenceCount);
    expect(postFeedCount).toBe(initialFeedCount);
  });

  it('should verify feed_records mutable updates modify cache without altering immutable evidence_ledger', () => {
    const itemV1 = createMockItem('cache-update-test', { version: 1 });
    itemV1.title = 'Initial Title V1';
    manager.persistItems([itemV1]);

    const evidId = `ev-${itemV1.id.replace(/[:/]/g, '-')}`;
    const feedId = `feed-${itemV1.id.replace(/[:/]/g, '-')}`;

    // Update item with newer title and updated payload, but same natural key and same contentHash
    const itemV2 = {
      ...itemV1,
      title: 'Updated Title V2'
    };
    const res2 = manager.persistItems([itemV2]);

    expect(res2.evidenceRecordsInserted).toBe(0);
    expect(res2.evidenceDuplicatesSkipped).toBe(1);
    expect(res2.feedRecordsUpdated).toBe(1);

    // feed_records must reflect the updated title
    const feedRow = db.prepare('SELECT title FROM feed_records WHERE id = ?').get(feedId) as any;
    expect(feedRow.title).toBe('Updated Title V2');

    // evidence_ledger MUST retain the original V1 source_title due to immutability
    const evidRow = db.prepare('SELECT source_title FROM evidence_ledger WHERE id = ?').get(evidId) as any;
    expect(evidRow.source_title).toBe('Initial Title V1');
  });
});

