// server/connectors/base.ts
// Provider-independent OSINT & Threat Intel Connector base contracts and resilience infrastructure

import crypto from 'node:crypto';
import type { SourceType, FeedCategory, FeedSeverity, VerificationStatus, EntityType } from '../db/schema.js';

export type { SourceType, FeedCategory, FeedSeverity, VerificationStatus, EntityType };

export type ConnectorCategory = 'geospatial' | 'threat_intel' | 'infrastructure' | 'news' | 'certificate';

export interface RateLimitConfig {
  capacity: number;          // Max burst tokens
  refillPerSecond: number;   // Refill rate per second
  maxWaitMs?: number;        // Max queuing timeout before rejecting (default: 10000ms)
}

export interface ConnectorQuery {
  target?: string;           // Domain, IP, CVE-ID, URL, etc.
  since?: string;            // ISO timestamp for incremental fetch
  limit?: number;            // Page size
  bbox?: [number, number, number, number]; // [minLon, minLat, maxLon, maxLat]
  category?: string;
  custom?: Record<string, unknown>;
}

export interface ExtractedEntity {
  type: EntityType | string;
  value: string;
  riskScore?: number;
  attributes?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface NormalizedEvidenceItem {
  id: string;                               // Natural key (e.g., "usgs:us7000test", "cisa_kev:CVE-2026-48356")
  caseId?: string | null;
  sourceConnectorId: string;                // e.g. "usgs", "cisa_kev"
  sourceName: string;                       // e.g. "USGS Earthquakes Telemetry"
  sourceUrl: string;                        // Upstream queried URL
  sourceType: SourceType;                   // Enum from schema.ts
  feedCategory: FeedCategory;               // Enum from schema.ts
  severity: FeedSeverity;                   // 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  title: string;
  summary: string | null;
  publishedAt: string | null;               // ISO-8601 upstream timestamp
  retrievedAt: string;                      // ISO-8601 ingestion timestamp
  verificationStatus: VerificationStatus;   // 'Observed' | 'Source-reported' | 'Corroborated' | 'Inferred' | 'Unverified' | 'Stale'
  confidenceScore: number;                  // 0.0 to 1.0
  contentHash: string;                      // SHA-256 hex string (64 characters)
  rawPayload: Record<string, unknown> | string;
  parsedPayload?: Record<string, unknown> | null;
  coordinates?: { lat: number; lon: number; depthKm?: number } | null;
  extractedEntities?: ExtractedEntity[];
}

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface ConnectorHealth {
  connectorId: string;
  name?: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  circuitState?: CircuitState;
  tokensAvailable?: number;
  latencyMs: number;
  p95LatencyMs: number;
  consecutiveFailures: number;
  totalRequests?: number;
  totalFailures?: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastErrorMessage: string | null;
  freshnessTimestamp?: string | null;
}

export interface IConnector {
  readonly id: string;
  readonly name: string;
  readonly category: ConnectorCategory | string;
  readonly rateLimitConfig: RateLimitConfig;
  fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]>;
  healthCheck(): Promise<ConnectorHealth>;
}

// ---------------------------------------------------------------------------
// Rate Limiting: Token Bucket
// ---------------------------------------------------------------------------

export class RateLimitExceededError extends Error {
  constructor(public readonly connectorId: string, public readonly waitMs: number) {
    super(`RATE_LIMIT_EXCEEDED: Connector '${connectorId}' token bucket depleted (wait: ${waitMs}ms exceeded max limit)`);
    this.name = 'RateLimitExceededError';
  }
}

export class TokenBucketLimiter {
  private tokens: number;
  private lastRefill: number;
  public readonly capacity: number;
  public readonly refillPerSec: number;
  private readonly getTime: () => number;

  constructor(capacity: number, refillPerSec: number, getTime: () => number = () => Date.now()) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.getTime = getTime;
    this.tokens = capacity;
    this.lastRefill = this.getTime();
  }

  private refill(): void {
    const now = this.getTime();
    const elapsedSec = Math.max(0, (now - this.lastRefill) / 1000);
    this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.refillPerSec);
    this.lastRefill = now;
  }

  tryConsume(cost: number = 1): boolean {
    this.refill();
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }

  async acquire(cost: number = 1, maxWaitMs: number = 10000, connectorId = 'connector'): Promise<void> {
    this.refill();
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return;
    }

    const needed = cost - this.tokens;
    const waitMs = Math.ceil((needed / this.refillPerSec) * 1000);

    if (waitMs > maxWaitMs) {
      throw new RateLimitExceededError(connectorId, waitMs);
    }

    await new Promise((resolve) => setTimeout(resolve, waitMs));
    this.refill();
    this.tokens = Math.max(0, this.tokens - cost);
  }

  get availableTokens(): number {
    this.refill();
    return Math.floor(this.tokens * 100) / 100;
  }

  getTokens(): number {
    this.refill();
    return Math.floor(this.tokens * 100) / 100;
  }
}

// Alias for TokenBucketLimiter
export const TokenBucket = TokenBucketLimiter;

// ---------------------------------------------------------------------------
// Exponential Backoff with AWS Full Jitter
// ---------------------------------------------------------------------------

export function calculateFullJitter(attempt: number, baseBackoffMs = 1000, maxBackoffMs = 16000): number {
  const exponential = baseBackoffMs * Math.pow(2, attempt);
  const ceiling = Math.min(maxBackoffMs, exponential);
  return Math.floor(Math.random() * (ceiling + 1));
}

export const FullJitter = {
  calculate: calculateFullJitter,
  async sleep(attempt: number, baseBackoffMs = 1000, maxBackoffMs = 16000): Promise<void> {
    const delay = calculateFullJitter(attempt, baseBackoffMs, maxBackoffMs);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }
};

export function defaultIsRetryable(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const errorObj = err as { code?: string; status?: number; statusCode?: number; message?: string };
  const nonRetryableCodes = [
    'SSRF_BLOCKED',
    'SSRF_INVALID_INPUT',
    'SSRF_DISALLOWED_PROTOCOL',
    'SSRF_CREDENTIALS_DISALLOWED',
    'XXE_ATTACK_DETECTED',
    'DTD_FORBIDDEN'
  ];
  if (errorObj.code && nonRetryableCodes.includes(errorObj.code)) return false;
  const status = errorObj.status ?? errorObj.statusCode;
  if (status === 400 || status === 401 || status === 403 || status === 404) return false;
  return true;
}

export async function withExponentialBackoff<T>(
  operation: (attempt: number) => Promise<T>,
  options: {
    maxAttempts?: number;
    baseBackoffMs?: number;
    maxBackoffMs?: number;
    isRetryable?: (error: unknown) => boolean;
  } = {}
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const baseBackoffMs = options.baseBackoffMs ?? 1000;
  const maxBackoffMs = options.maxBackoffMs ?? 16000;
  const isRetryable = options.isRetryable ?? defaultIsRetryable;

  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await operation(attempt);
    } catch (err: unknown) {
      lastError = err;
      if (attempt >= maxAttempts - 1 || !isRetryable(err)) {
        throw err;
      }
      const delayMs = calculateFullJitter(attempt, baseBackoffMs, maxBackoffMs);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastError;
}

// ---------------------------------------------------------------------------
// Circuit Breaker State Machine
// ---------------------------------------------------------------------------

export class CircuitBreakerOpenError extends Error {
  constructor(public readonly connectorId: string, public readonly cooldownRemainingMs: number) {
    super(`CIRCUIT_BREAKER_OPEN: Requests to connector '${connectorId}' rejected fast (${cooldownRemainingMs}ms cooldown remaining)`);
    this.name = 'CircuitBreakerOpenError';
  }
}

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  cooldownMs?: number;
}

export class CircuitBreaker {
  private state: CircuitState = 'CLOSED';
  private consecutiveFailures = 0;
  private lastFailureTime = 0;
  public readonly failureThreshold: number;
  public readonly cooldownMs: number;

  constructor(optionsOrThreshold: CircuitBreakerOptions | number = 5, cooldownMs = 30000) {
    if (typeof optionsOrThreshold === 'object' && optionsOrThreshold !== null) {
      this.failureThreshold = optionsOrThreshold.failureThreshold ?? 5;
      this.cooldownMs = optionsOrThreshold.cooldownMs ?? 30000;
    } else {
      this.failureThreshold = optionsOrThreshold;
      this.cooldownMs = cooldownMs;
    }
  }

  recordFailure(): void {
    this.consecutiveFailures++;
    this.lastFailureTime = Date.now();
    if (this.consecutiveFailures >= this.failureThreshold) {
      this.state = 'OPEN';
    }
  }

  recordSuccess(): void {
    this.consecutiveFailures = 0;
    this.state = 'CLOSED';
  }

  isOpen(): boolean {
    if (this.state === 'OPEN') {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.cooldownMs) {
        this.state = 'HALF_OPEN';
        return false; // Trial request allowed
      }
      return true;
    }
    return false;
  }

  getState(): CircuitState {
    if (this.state === 'OPEN' && Date.now() - this.lastFailureTime >= this.cooldownMs) {
      return 'HALF_OPEN';
    }
    return this.state;
  }

  get currentState(): CircuitState {
    return this.getState();
  }

  get failureCount(): number {
    return this.consecutiveFailures;
  }

  get cooldownRemaining(): number {
    if (this.state !== 'OPEN') return 0;
    const remaining = this.cooldownMs - (Date.now() - this.lastFailureTime);
    return Math.max(0, remaining);
  }

  async execute<T>(fn: () => Promise<T>, connectorId = 'connector'): Promise<T> {
    if (this.isOpen()) {
      throw new CircuitBreakerOpenError(connectorId, this.cooldownRemaining);
    }
    try {
      const result = await fn();
      this.recordSuccess();
      return result;
    } catch (err) {
      this.recordFailure();
      throw err;
    }
  }
}

// ---------------------------------------------------------------------------
// Canonical Fingerprinting
// ---------------------------------------------------------------------------

export function computeCanonicalFingerprint(obj: unknown): string {
  function canonicalize(val: unknown): unknown {
    if (val === null || typeof val !== 'object') {
      return val;
    }
    if (Array.isArray(val)) {
      return val.map(canonicalize);
    }
    const sortedKeys = Object.keys(val as Record<string, unknown>).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      result[key] = canonicalize((val as Record<string, unknown>)[key]);
    }
    return result;
  }

  const canonicalObj = canonicalize(obj);
  const canonicalString = JSON.stringify(canonicalObj);
  return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Base Connector Abstract Class
// ---------------------------------------------------------------------------

export abstract class BaseConnector implements IConnector {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly category: ConnectorCategory | string;
  abstract readonly rateLimitConfig: RateLimitConfig;

  protected limiter!: TokenBucketLimiter;
  protected breaker: CircuitBreaker = new CircuitBreaker(5, 30000);

  protected latencies: number[] = [];
  protected totalRequests = 0;
  protected totalFailures = 0;
  protected lastSuccessAt: string | null = null;
  protected lastFailureAt: string | null = null;
  protected lastErrorMessage: string | null = null;
  protected freshnessTimestamp: string | null = null;

  protected initRateLimiter(): void {
    if (!this.limiter) {
      this.limiter = new TokenBucketLimiter(
        this.rateLimitConfig.capacity,
        this.rateLimitConfig.refillPerSecond
      );
    }
  }

  abstract fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]>;

  async executeGuarded<T>(operation: () => Promise<T>): Promise<T> {
    this.initRateLimiter();
    await this.limiter.acquire(1, this.rateLimitConfig.maxWaitMs ?? 10000, this.id);

    const start = performance.now();
    this.totalRequests++;

    try {
      const result = await this.breaker.execute(async () => {
        return await withExponentialBackoff(() => operation(), {
          maxAttempts: 3,
          baseBackoffMs: 1000,
          maxBackoffMs: 8000
        });
      }, this.id);

      const elapsed = Math.round(performance.now() - start);
      this.recordLatency(elapsed);
      this.lastSuccessAt = new Date().toISOString();
      return result;
    } catch (err: unknown) {
      this.totalFailures++;
      this.lastFailureAt = new Date().toISOString();
      this.lastErrorMessage = err instanceof Error ? err.message : String(err);
      throw err;
    }
  }

  protected recordLatency(ms: number): void {
    this.latencies.push(ms);
    if (this.latencies.length > 50) {
      this.latencies.shift();
    }
  }

  async healthCheck(): Promise<ConnectorHealth> {
    this.initRateLimiter();
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const p95Idx = Math.floor(sorted.length * 0.95);
    const p95LatencyMs = sorted.length > 0 ? sorted[p95Idx] : 0;
    const latestLatencyMs = this.latencies.length > 0 ? this.latencies[this.latencies.length - 1] : 0;

    let status: ConnectorHealth['status'] = 'healthy';
    if (this.breaker.currentState === 'OPEN') {
      status = 'unhealthy';
    } else if (this.breaker.currentState === 'HALF_OPEN' || this.breaker.failureCount > 0 || p95LatencyMs > 3000) {
      status = 'degraded';
    }

    return {
      connectorId: this.id,
      name: this.name,
      status,
      circuitState: this.breaker.currentState,
      tokensAvailable: this.limiter.availableTokens,
      latencyMs: latestLatencyMs,
      p95LatencyMs,
      consecutiveFailures: this.breaker.failureCount,
      totalRequests: this.totalRequests,
      totalFailures: this.totalFailures,
      lastSuccessAt: this.lastSuccessAt,
      lastFailureAt: this.lastFailureAt,
      lastErrorMessage: this.lastErrorMessage,
      freshnessTimestamp: this.freshnessTimestamp
    };
  }
}
