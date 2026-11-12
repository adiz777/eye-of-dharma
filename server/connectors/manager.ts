// server/connectors/manager.ts
// Central Connector Manager & Orchestrator for EYE OF DHARMA

import crypto from 'node:crypto';
import type Database from 'better-sqlite3';
import {
  computeCanonicalFingerprint,
  type IConnector,
  type ConnectorQuery,
  type NormalizedEvidenceItem,
  type ConnectorHealth
} from './base.js';
import { UsgsEarthquakeConnector } from './usgs.js';
import { NasaEonetConnector } from './eonet.js';
import { CisaConnector } from './cisa.js';
import { RssFeedConnector } from './rss.js';
import { CrtShConnector } from './crtsh.js';
import { DnsRdapConnector } from './dns_rdap.js';
import { recordAuditEvent } from '../security/audit.js';

export { computeCanonicalFingerprint };

export interface IngestionResult {
  connectorId: string;
  itemsFetched: number;
  feedRecordsUpdated: number;
  evidenceRecordsInserted: number;
  evidenceDuplicatesSkipped: number;
  error?: string;
  durationMs: number;
}

export interface RefreshSummary {
  refreshed: string[];
  count: number;
  totalFetched: number;
  totalInsertedEvidence: number;
  totalUpdatedFeeds: number;
  totalSkippedDuplicates: number;
  results: Record<string, IngestionResult>;
  errors: Array<{ connectorId: string; error: string }>;
}

export class ConnectorManager {
  private connectors: Map<string, IConnector> = new Map();
  private aliasMap: Map<string, string> = new Map();
  private db: Database.Database;
  private pollingTimers: Map<string, NodeJS.Timeout> = new Map();
  private inFlightRuns: Set<string> = new Set();

  constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * Registers a connector under its primary id and optional aliases
   */
  register(connector: IConnector, aliases: string[] = []): void {
    const primaryId = connector.id;
    this.connectors.set(primaryId, connector);
    this.aliasMap.set(primaryId.toLowerCase(), primaryId);

    for (const alias of aliases) {
      this.aliasMap.set(alias.toLowerCase(), primaryId);
    }
  }

  get(id: string): IConnector | undefined {
    const resolvedId = this.aliasMap.get(id.toLowerCase()) || id;
    return this.connectors.get(resolvedId);
  }

  getAll(): IConnector[] {
    return Array.from(this.connectors.values());
  }

  has(id: string): boolean {
    const resolvedId = this.aliasMap.get(id.toLowerCase()) || id;
    return this.connectors.has(resolvedId);
  }

  async healthAll(): Promise<Record<string, ConnectorHealth>> {
    const healthMap: Record<string, ConnectorHealth> = {};
    for (const [id, connector] of this.connectors.entries()) {
      healthMap[id] = await connector.healthCheck();
    }
    return healthMap;
  }

  /**
   * Persists normalized items into feed_records and evidence_ledger.
   * STRICT IMMUTABILITY COMPLIANCE:
   * 1. feed_records: Updated/Inserted via REPLACE or ON CONFLICT UPDATE (mutable UI cache).
   * 2. evidence_ledger: Checked beforehand by content_fingerprint or id.
   *    If it exists, skip insert so trigger trg_prevent_evidence_replace is never tripped!
   */
  persistItems(items: NormalizedEvidenceItem[]): {
    feedRecordsUpdated: number;
    evidenceRecordsInserted: number;
    evidenceDuplicatesSkipped: number;
  } {
    if (items.length === 0) {
      return { feedRecordsUpdated: 0, evidenceRecordsInserted: 0, evidenceDuplicatesSkipped: 0 };
    }

    const checkEvidenceStmt = this.db.prepare(
      'SELECT id FROM evidence_ledger WHERE id = ? OR content_fingerprint = ?'
    );

    const insertEvidenceStmt = this.db.prepare(`
      INSERT INTO evidence_ledger (
        id, case_id, source_url, source_type, source_title,
        content_fingerprint, raw_content, parsed_content,
        verification_status, confidence_score, retrieved_at,
        published_at, recorded_by, is_synthetic, notes, immutable_lock
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?,
        ?, 'SYSTEM', 0, ?, 1
      )
    `);

    const upsertFeedStmt = this.db.prepare(`
      INSERT INTO feed_records (
        id, feed_name, external_id, title, category,
        severity, source_url, published_at, ingested_at,
        summary, payload, geocoding_lat, geocoding_lon, is_synthetic
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, 0
      )
      ON CONFLICT(id) DO UPDATE SET
        title = excluded.title,
        severity = excluded.severity,
        published_at = excluded.published_at,
        ingested_at = excluded.ingested_at,
        summary = excluded.summary,
        payload = excluded.payload,
        geocoding_lat = excluded.geocoding_lat,
        geocoding_lon = excluded.geocoding_lon
    `);

    let feedRecordsUpdated = 0;
    let evidenceRecordsInserted = 0;
    let evidenceDuplicatesSkipped = 0;

    const tx = this.db.transaction((records: NormalizedEvidenceItem[]) => {
      for (const item of records) {
        // 1. Upsert into feed_records (mutable cache)
        const feedId = `feed-${item.id.replace(/[:/]/g, '-')}`;
        const rawPayloadStr = typeof item.rawPayload === 'string'
          ? item.rawPayload
          : JSON.stringify(item.rawPayload);

        upsertFeedStmt.run(
          feedId,
          item.sourceConnectorId.toUpperCase(),
          item.id,
          item.title,
          item.feedCategory,
          item.severity,
          item.sourceUrl,
          item.publishedAt || item.retrievedAt,
          item.retrievedAt,
          item.summary,
          rawPayloadStr,
          item.coordinates?.lat ?? null,
          item.coordinates?.lon ?? null
        );
        feedRecordsUpdated++;

        // 2. Insert into evidence_ledger (Strict Immutability Compliance)
        const evidenceId = `ev-${item.id.replace(/[:/]/g, '-')}`;
        const existing = checkEvidenceStmt.get(evidenceId, item.contentHash);

        if (existing) {
          evidenceDuplicatesSkipped++;
        } else {
          const parsedStr = item.parsedPayload ? JSON.stringify(item.parsedPayload) : null;
          insertEvidenceStmt.run(
            evidenceId,
            item.caseId || null,
            item.sourceUrl,
            item.sourceType,
            item.title,
            item.contentHash,
            rawPayloadStr,
            parsedStr,
            item.verificationStatus,
            item.confidenceScore,
            item.retrievedAt,
            item.publishedAt,
            item.summary || null
          );
          evidenceRecordsInserted++;
        }
      }
    });

    tx(items);

    return {
      feedRecordsUpdated,
      evidenceRecordsInserted,
      evidenceDuplicatesSkipped
    };
  }

  async refreshConnector(connectorId: string, query?: ConnectorQuery): Promise<IngestionResult> {
    const connector = this.get(connectorId);
    if (!connector) {
      throw new Error(`Connector '${connectorId}' not found in registry`);
    }

    const canonicalId = connector.id;
    if (this.inFlightRuns.has(canonicalId)) {
      return {
        connectorId,
        itemsFetched: 0,
        feedRecordsUpdated: 0,
        evidenceRecordsInserted: 0,
        evidenceDuplicatesSkipped: 0,
        error: 'INGESTION_IN_PROGRESS',
        durationMs: 0
      };
    }

    this.inFlightRuns.add(canonicalId);
    const start = performance.now();

    try {
      // Determine query options for CISA if requested by alias
      const effectiveQuery = { ...query };
      if (connectorId.toUpperCase() === 'CISA_ALERTS' || connectorId.toUpperCase() === 'CISA_ADVISORIES') {
        effectiveQuery.category = 'ADVISORY';
      } else if (connectorId.toUpperCase() === 'CISA_KEV') {
        effectiveQuery.category = 'KEV';
      }

      const items = await connector.fetch(effectiveQuery);
      const persistStats = this.persistItems(items);
      const durationMs = Math.round(performance.now() - start);

      recordAuditEvent(this.db, {
        actor: 'CONNECTOR_MANAGER',
        action: 'FEED_REFRESHED',
        entity_type: 'FEED',
        entity_id: connectorId,
        details: {
          itemsFetched: items.length,
          evidenceInserted: persistStats.evidenceRecordsInserted,
          duplicatesSkipped: persistStats.evidenceDuplicatesSkipped,
          durationMs
        },
        status: 'SUCCESS'
      });

      return {
        connectorId,
        itemsFetched: items.length,
        feedRecordsUpdated: persistStats.feedRecordsUpdated,
        evidenceRecordsInserted: persistStats.evidenceRecordsInserted,
        evidenceDuplicatesSkipped: persistStats.evidenceDuplicatesSkipped,
        durationMs
      };
    } catch (err: unknown) {
      const durationMs = Math.round(performance.now() - start);
      const errorMsg = err instanceof Error ? err.message : String(err);

      recordAuditEvent(this.db, {
        actor: 'CONNECTOR_MANAGER',
        action: 'FEED_REFRESH_FAILED',
        entity_type: 'FEED',
        entity_id: connectorId,
        details: { error: errorMsg, durationMs },
        status: 'FAILURE'
      });

      return {
        connectorId,
        itemsFetched: 0,
        feedRecordsUpdated: 0,
        evidenceRecordsInserted: 0,
        evidenceDuplicatesSkipped: 0,
        error: errorMsg,
        durationMs
      };
    } finally {
      this.inFlightRuns.delete(canonicalId);
    }
  }

  async refreshAll(connectorIds?: string[]): Promise<RefreshSummary> {
    const targetIds = connectorIds && connectorIds.length > 0
      ? connectorIds
      : Array.from(this.connectors.keys());

    const summary: RefreshSummary = {
      refreshed: [],
      count: 0,
      totalFetched: 0,
      totalInsertedEvidence: 0,
      totalUpdatedFeeds: 0,
      totalSkippedDuplicates: 0,
      results: {},
      errors: []
    };

    for (const id of targetIds) {
      if (!this.has(id)) {
        summary.errors.push({ connectorId: id, error: `Connector '${id}' not registered` });
        continue;
      }

      const res = await this.refreshConnector(id);
      summary.refreshed.push(id);
      summary.results[id] = res;
      summary.totalFetched += res.itemsFetched;
      summary.totalInsertedEvidence += res.evidenceRecordsInserted;
      summary.totalUpdatedFeeds += res.feedRecordsUpdated;
      summary.totalSkippedDuplicates += res.evidenceDuplicatesSkipped;

      if (res.error) {
        summary.errors.push({ connectorId: id, error: res.error });
      }
    }

    summary.count = summary.refreshed.length;
    return summary;
  }

  startPolling(connectorId: string, intervalMs: number): void {
    if (this.pollingTimers.has(connectorId)) {
      this.stopPolling(connectorId);
    }
    const timer = setInterval(() => {
      this.refreshConnector(connectorId).catch((err) => {
        console.error(`[ConnectorManager] Polling error on ${connectorId}:`, err);
      });
    }, intervalMs);
    this.pollingTimers.set(connectorId, timer);
  }

  stopPolling(connectorId?: string): void {
    if (connectorId) {
      const timer = this.pollingTimers.get(connectorId);
      if (timer) {
        clearInterval(timer);
        this.pollingTimers.delete(connectorId);
      }
    } else {
      for (const [, timer] of this.pollingTimers.entries()) {
        clearInterval(timer);
      }
      this.pollingTimers.clear();
    }
  }
}

/**
 * Creates and registers all standard Priority A connectors for EYE OF DHARMA
 */
export function createDefaultConnectorManager(db: Database.Database): ConnectorManager {
  const manager = new ConnectorManager(db);

  const usgs = new UsgsEarthquakeConnector();
  const eonet = new NasaEonetConnector();
  const cisa = new CisaConnector();
  const crtsh = new CrtShConnector();
  const dnsRdap = new DnsRdapConnector();
  const rss = new RssFeedConnector();

  manager.register(usgs, ['USGS', 'usgs', 'usgs_earthquakes', 'EARTHQUAKES']);
  manager.register(eonet, ['NASA_EONET', 'eonet', 'nasa_eonet', 'HAZARDS']);
  manager.register(cisa, ['CISA_KEV', 'cisa_kev', 'CISA_ALERTS', 'cisa_advisories', 'CISA', 'cisa_intel']);
  manager.register(crtsh, ['CRT_SH', 'crtsh', 'crt_sh', 'CERTIFICATES']);
  manager.register(dnsRdap, ['DNS_RDAP', 'dns_rdap', 'dns', 'rdap', 'NETWORK']);
  manager.register(rss, ['RSS', 'rss', 'rss_feed', 'NEWS']);

  return manager;
}
