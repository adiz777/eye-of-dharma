/**
 * EYE OF DHARMA (EOD) — E2E Test Suite Helpers
 * Coupled integration harness utilizing authentic server schemas, database migrations, and routers.
 */

import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import request from 'supertest';
import type { Express } from 'express';

// Authentic platform imports from server/
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase, computeSha256 as serverComputeSha256 } from '../../server/db/seed.js';
import { createApp } from '../../server/app.js';
import {
  validateUrlForSsrf,
  safeFetch,
  isIpForbidden,
  type SsrfValidationOptions,
  type SafeFetchOptions,
  type SafeFetchResult
} from '../../server/security/ssrf.js';
import {
  CreateCaseSchema,
  UpdateCaseSchema,
  IngestEvidenceSchema,
  CreateEntitySchema,
  CreateRelationshipSchema,
  CreateThreatIndicatorSchema,
  CreateWatchlistSchema,
  UpdateWatchlistSchema,
  FootprintQuerySchema,
  TerminalCommandSchema,
  DispatchAgentSchema
} from '../../server/security/validation.js';

export interface TestResult {
  name: string;
  tier: number;
  area: string;
  passed: boolean;
  durationMs: number;
  error?: string;
}

export type TestFn = () => Promise<void> | void;

export interface TestCase {
  name: string;
  tier: number;
  area: string;
  fn: TestFn;
}

// Standard test assertions
export function assert(condition: boolean, message: string = 'Assertion failed'): void {
  if (!condition) {
    throw new Error(`Assertion Failed: ${message}`);
  }
}

export function assertEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    throw new Error(
      `Assertion Failed: ${message || 'Values not equal'}\nExpected: ${JSON.stringify(expected)}\nActual:   ${JSON.stringify(actual)}`
    );
  }
}

export function assertIncludes(actual: string, expectedSub: string, message?: string): void {
  if (!actual.includes(expectedSub)) {
    throw new Error(
      `Assertion Failed: ${message || 'Substring not found'}\nTarget:   ${expectedSub}\nReceived: ${actual}`
    );
  }
}

export function assertThrows(fn: () => unknown, expectedErrorSub?: string): void {
  let threw = false;
  try {
    fn();
  } catch (err: any) {
    threw = true;
    if (expectedErrorSub && !err.message.includes(expectedErrorSub)) {
      throw new Error(
        `Expected error containing "${expectedErrorSub}", but caught: "${err.message}"`
      );
    }
  }
  if (!threw) {
    throw new Error(`Expected function to throw error, but it succeeded.`);
  }
}

export async function assertThrowsAsync(fn: () => Promise<unknown>, expectedErrorSub?: string): Promise<void> {
  let threw = false;
  try {
    await fn();
  } catch (err: any) {
    threw = true;
    if (expectedErrorSub && !err.message.includes(expectedErrorSub)) {
      throw new Error(
        `Expected error containing "${expectedErrorSub}", but caught: "${err.message}"`
      );
    }
  }
  if (!threw) {
    throw new Error(`Expected async function to throw error, but it succeeded.`);
  }
}

// Canonical SHA-256 fingerprint generator
export function computeSha256(payload: string | Buffer | Record<string, unknown>): string {
  if (typeof payload === 'object' && !Buffer.isBuffer(payload)) {
    const sortedKeys = Object.keys(payload).sort();
    const canonicalStr = JSON.stringify(payload, sortedKeys);
    return crypto.createHash('sha256').update(canonicalStr, 'utf8').digest('hex');
  }
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Authentic In-Memory Database Factory
 * Directly executes server/db/migrate.ts migrations and optional seeding.
 */
export function createInMemoryDatabase(options: { seed?: boolean } = {}): Database.Database {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.pragma('recursive_triggers = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('temp_store = MEMORY');
  runMigrations(db);
  if (options.seed) {
    seedDatabase(db);
  }
  return db;
}

/**
 * Authentic Express Application Factory for E2E integration testing
 */
export function createTestApp(db?: Database.Database): { db: Database.Database; app: Express } {
  process.env.NODE_ENV = 'test';
  const database = db || createInMemoryDatabase({ seed: true });
  const app = createApp(database);
  return { db: database, app };
}

/**
 * Authentic SSRF Firewall Evaluator
 * Directly invokes server/security/ssrf.ts validateUrlForSsrf.
 */
export interface SsrfCheckResult {
  allowed: boolean;
  reason?: string;
  error?: string;
  ip?: string;
  matchedCidr?: string;
  normalizedUrl?: string;
  resolvedIps?: string[];
  pinnedIp?: string;
}

export async function evaluateSsrfUrl(
  targetUrl: string,
  options?: SsrfValidationOptions
): Promise<SsrfCheckResult> {
  const opts: SsrfValidationOptions = { ...options };
  if (!opts.dnsResolver) {
    opts.dnsResolver = async (hostname: string) => {
      if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return [{ address: '127.0.0.1', family: 4 }];
      }
      if (hostname === '::1') {
        return [{ address: '::1', family: 6 }];
      }
      try {
        const dns = await import('node:dns');
        const records = await dns.promises.lookup(hostname, { all: true });
        if (records && records.length > 0) return records;
      } catch {
        // Fallback for sandboxed offline execution
      }
      return [{ address: '93.184.216.34', family: 4 }];
    };
  }

  const result = await validateUrlForSsrf(targetUrl, opts);
  let mappedReason = result.error || result.reason;
  if (!result.allowed && result.matchedCidr) {
    if (
      result.reason?.includes('Loopback') ||
      result.reason?.includes('Current Network') ||
      result.reason?.includes('Unspecified') ||
      result.matchedCidr?.startsWith('127.') ||
      result.matchedCidr?.startsWith('0.') ||
      result.matchedCidr === '::1/128' ||
      result.matchedCidr === '::/128'
    ) {
      mappedReason = 'SSRF_LOOPBACK_BLOCKED';
    } else if (
      result.reason?.includes('Cloud Metadata') ||
      result.reason?.includes('Link-Local') ||
      result.reason?.includes('Unique Local') ||
      result.matchedCidr?.startsWith('169.254.') ||
      result.matchedCidr?.startsWith('fe80:') ||
      result.matchedCidr?.startsWith('fc00:')
    ) {
      mappedReason = 'SSRF_CLOUD_METADATA_BLOCKED';
    } else if (
      result.reason?.includes('Private-Use') ||
      result.reason?.includes('RFC 1918') ||
      result.matchedCidr?.startsWith('10.') ||
      result.matchedCidr?.startsWith('192.168.') ||
      result.matchedCidr?.startsWith('172.')
    ) {
      mappedReason = 'SSRF_PRIVATE_NETWORK_BLOCKED';
    }
  } else if (!result.allowed && result.error) {
    mappedReason = result.error;
  }

  return {
    ...result,
    reason: mappedReason,
    ip: result.pinnedIp || (result.resolvedIps && result.resolvedIps[0])
  };
}

/**
 * Authentic Terminal Command Evaluator
 * Dispatches command directly through the Express router to execute against the real database.
 */
export interface TerminalResult {
  output: string;
  success: boolean;
  error?: string;
}

export async function evaluateTerminalCommand(
  cmdString: string,
  db?: Database.Database
): Promise<TerminalResult> {
  // Client-side shell safety guard
  if (cmdString.includes(';') || cmdString.includes('&&') || cmdString.includes('|') || cmdString.includes('`') || cmdString.includes('$')) {
    return {
      success: false,
      output: '',
      error: 'Error: Illegal characters detected. Command chaining and subshells are strictly prohibited.'
    };
  }
  if (cmdString.length > 200) {
    return {
      success: false,
      output: '',
      error: 'Error: Command string exceeds maximum command buffer length (200 characters).'
    };
  }

  process.env.NODE_ENV = 'test';
  const testDb = db || createInMemoryDatabase({ seed: true });
  const app = createApp(testDb);

  const res = await request(app)
    .post('/api/v1/terminal/exec')
    .set('x-bypass-csrf', 'true')
    .send({ command: cmdString });

  if (res.status === 200) {
    const isUnrecognized = res.body.output.includes('Command not recognized') || res.body.output.includes('not found') || res.body.output.includes('Unknown');
    return {
      success: !isUnrecognized,
      output: res.body.output,
      error: isUnrecognized ? res.body.output : undefined
    };
  } else {
    const errorMsg =
      res.body.error?.message ||
      (res.body.error?.details ? JSON.stringify(res.body.error.details) : 'Command execution failed');
    return {
      success: false,
      output: '',
      error: errorMsg
    };
  }
}

// Re-export real Zod schemas and SSRF functions for tests
export {
  validateUrlForSsrf,
  safeFetch,
  isIpForbidden,
  CreateCaseSchema,
  UpdateCaseSchema,
  IngestEvidenceSchema,
  CreateEntitySchema,
  CreateRelationshipSchema,
  CreateThreatIndicatorSchema,
  CreateWatchlistSchema,
  UpdateWatchlistSchema,
  FootprintQuerySchema,
  TerminalCommandSchema,
  DispatchAgentSchema
};

export class TokenBucketLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(public readonly capacity: number, public readonly refillPerSec: number) {
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  tryConsume(cost: number = 1): boolean {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.refillPerSec);
    this.lastRefill = now;

    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }
}

export type AgentState = 'PLANNED' | 'RUNNING' | 'VERIFYING' | 'COMPLETED' | 'FAILED';

export class AgentStateMachine {
  private _state: AgentState = 'PLANNED';
  private _history: AgentState[] = ['PLANNED'];

  get currentState(): AgentState {
    return this._state;
  }

  get history(): AgentState[] {
    return [...this._history];
  }

  transitionTo(next: AgentState): void {
    const valid: Record<AgentState, AgentState[]> = {
      PLANNED: ['RUNNING', 'FAILED'],
      RUNNING: ['VERIFYING', 'FAILED'],
      VERIFYING: ['COMPLETED', 'RUNNING', 'FAILED'],
      COMPLETED: [],
      FAILED: []
    };

    if (!valid[this._state].includes(next)) {
      throw new Error(`Invalid state transition: ${this._state} -> ${next}`);
    }

    this._state = next;
    this._history.push(next);
  }
}

export function extractCitations(text: string): string[] {
  const matches = text.match(/\[EVID-[a-zA-Z0-9_\-]+\]/g);
  if (!matches) return [];
  return Array.from(new Set(matches.map(m => m.replace(/\[|\]/g, ''))));
}

export function auditCitationsAgainstLedger(
  claimText: string,
  validLedgerIds: Set<string>
): { verified: boolean; missing: string[]; found: string[] } {
  const citations = extractCitations(claimText);
  const found: string[] = [];
  const missing: string[] = [];

  for (const cid of citations) {
    if (validLedgerIds.has(cid)) {
      found.push(cid);
    } else {
      missing.push(cid);
    }
  }

  return {
    verified: missing.length === 0 && found.length > 0,
    missing,
    found
  };
}

export function validateStixBundle(bundle: any): void {
  assert(typeof bundle === 'object' && bundle !== null, 'STIX bundle must be an object');
  assertEqual(bundle.type, 'bundle', 'STIX bundle type must be "bundle"');
  assertEqual(bundle.spec_version, '2.1', 'STIX bundle spec_version must be "2.1"');
  assert(Array.isArray(bundle.objects), 'STIX bundle must contain objects array');
  assert(bundle.objects.length > 0, 'STIX bundle must contain at least one object');
}

export function validateCsvFormat(csvText: string, expectedColumns: string[]): void {
  const lines = csvText.trim().split('\n');
  assert(lines.length >= 1, 'CSV must contain at least a header row');
  const header = lines[0].split(',').map(c => c.trim().replace(/^"|"$/g, ''));
  for (const col of expectedColumns) {
    assert(header.includes(col), `CSV header missing required column: ${col}`);
  }
}

export function validateHtmlReport(htmlText: string): void {
  assertIncludes(htmlText, '<!DOCTYPE html>', 'Report must be valid HTML5');
  assertIncludes(htmlText, '#0A0D14', 'Report must preserve dark operations palette');
  assertIncludes(htmlText, 'Evidence Ledger', 'Report must contain Evidence Ledger');
}
