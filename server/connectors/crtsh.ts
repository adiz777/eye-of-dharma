// server/connectors/crtsh.ts
// Certificate Transparency Connector for crt.sh with SAN & Wildcard Parsing

import crypto from 'node:crypto';
import { safeFetch } from '../security/ssrf.js';
import {
  BaseConnector,
  computeCanonicalFingerprint,
  type ConnectorQuery,
  type NormalizedEvidenceItem,
  type RateLimitConfig,
  type ExtractedEntity
} from './base.js';
import type { FeedRecord } from '../db/schema.js';

export interface CrtShEntry {
  issuer_ca_id?: number;
  issuer_name?: string;
  common_name?: string;
  name_value?: string;
  id: number;
  entry_timestamp?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
}

export interface ParsedSanResult {
  subdomains: string[];
  wildcards: string[];
  emails: string[];
  allDomains: string[];
}

/**
 * Extracts and sanitizes subdomains, wildcards, and emails from multi-line SAN entries
 */
export function parseSanEntries(nameValue?: string, commonName?: string): ParsedSanResult {
  const subdomains = new Set<string>();
  const wildcards = new Set<string>();
  const emails = new Set<string>();
  const allDomains = new Set<string>();

  const rawLines: string[] = [];
  if (nameValue) {
    rawLines.push(...nameValue.split(/\r?\n/));
  }
  if (commonName) {
    rawLines.push(commonName);
  }

  for (const raw of rawLines) {
    const trimmed = raw.trim().toLowerCase();
    if (!trimmed) continue;

    // Email address detection
    if (trimmed.includes('@')) {
      if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed)) {
        emails.add(trimmed);
      }
      continue;
    }

    // Wildcard domain handling
    if (trimmed.startsWith('*.')) {
      wildcards.add(trimmed);
      const stripped = trimmed.slice(2).replace(/^\.+/, '');
      if (stripped && isValidDomain(stripped)) {
        subdomains.add(stripped);
        allDomains.add(stripped);
      }
      allDomains.add(trimmed);
      continue;
    }

    if (isValidDomain(trimmed)) {
      subdomains.add(trimmed);
      allDomains.add(trimmed);
    }
  }

  return {
    subdomains: Array.from(subdomains).sort(),
    wildcards: Array.from(wildcards).sort(),
    emails: Array.from(emails).sort(),
    allDomains: Array.from(allDomains).sort()
  };
}

export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  return domainPattern.test(domain);
}

export class CrtShConnector extends BaseConnector {
  public readonly id = 'CRT_SH';
  public readonly name = 'crt.sh Certificate Transparency';
  public readonly category = 'certificate' as const;
  public readonly rateLimitConfig: RateLimitConfig = { capacity: 2, refillPerSecond: 0.33 };

  public async fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]> {
    const rawTarget = query?.target?.trim();
    if (!rawTarget) {
      return [];
    }

    // Clean target (strip protocol, port, or path)
    const cleanTarget = rawTarget
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .split(':')[0]
      .toLowerCase();

    const queryParam = cleanTarget;
    const url = `https://crt.sh/?q=${encodeURIComponent(queryParam)}&output=json`;

    return await this.executeGuarded(async () => {
      let data = '';
      let statusCode = 200;

      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const res = await safeFetch(url, {
            timeoutMs: 8000,
            maxBytes: 5 * 1024 * 1024,
            headers: {
              Accept: 'application/json, text/plain',
              'User-Agent': 'EyeOfDharma-Collector/1.0'
            }
          });

          statusCode = res.statusCode;
          data = res.data;

          if (statusCode === 502 || statusCode === 504 || statusCode >= 500) {
            throw new Error(`UPSTREAM_GATEWAY_ERROR: HTTP ${statusCode}`);
          }

          break; // Succeeded
        } catch (err: unknown) {
          if (attempt === 1) {
            // Graceful degradation: return empty array rather than crashing
            return [];
          }
          const sleepMs = 1000 + Math.floor(Math.random() * 1000);
          await new Promise((r) => setTimeout(r, sleepMs));
        }
      }

      // Parse JSON safely
      let entries: CrtShEntry[] = [];
      try {
        const trimmed = data.trim();
        if (!trimmed || trimmed === '[]') {
          return [];
        }
        entries = JSON.parse(trimmed);
        if (!Array.isArray(entries)) {
          entries = [];
        }
      } catch {
        // crt.sh may return HTML on error
        return [];
      }

      const normalizedItems: NormalizedEvidenceItem[] = [];
      const retrievedAt = new Date().toISOString();

      for (const entry of entries) {
        if (!entry || typeof entry.id !== 'number') continue;

        const parsedSan = parseSanEntries(entry.name_value, entry.common_name);
        const rawJson = JSON.stringify(entry);
        const contentHash = computeCanonicalFingerprint(entry);
        const naturalKey = `crtsh:${entry.id}:${contentHash.slice(0, 16)}`;

        const entities: ExtractedEntity[] = [];
        for (const sub of parsedSan.subdomains) {
          entities.push({ type: 'DOMAIN', value: sub });
        }
        if (entry.serial_number) {
          entities.push({
            type: 'CERTIFICATE',
            value: entry.serial_number,
            attributes: { issuer: entry.issuer_name }
          });
        }
        if (entry.issuer_name) {
          entities.push({ type: 'ORGANIZATION', value: entry.issuer_name });
        }

        normalizedItems.push({
          id: naturalKey,
          sourceConnectorId: this.id,
          sourceName: this.name,
          sourceUrl: url,
          sourceType: 'CRT_SH',
          feedCategory: 'CERTIFICATE',
          severity: 'INFO',
          title: `Certificate: ${entry.common_name || cleanTarget} (ID: ${entry.id})`,
          summary: `Issued by ${entry.issuer_name || 'Unknown CA'}. Validity: ${entry.not_before || 'N/A'} to ${entry.not_after || 'N/A'}. SAN count: ${parsedSan.subdomains.length}`,
          publishedAt: entry.not_before || entry.entry_timestamp || null,
          retrievedAt,
          verificationStatus: 'Observed',
          confidenceScore: 0.95,
          contentHash,
          rawPayload: entry as unknown as Record<string, unknown>,
          parsedPayload: {
            id: entry.id,
            common_name: entry.common_name,
            issuer_name: entry.issuer_name,
            subdomains: parsedSan.subdomains,
            wildcards: parsedSan.wildcards,
            emails: parsedSan.emails
          },
          extractedEntities: entities
        });
      }

      this.freshnessTimestamp = retrievedAt;
      return normalizedItems;
    });
  }

  public toFeedRecord(item: NormalizedEvidenceItem): FeedRecord {
    const raw = typeof item.rawPayload === 'string' ? JSON.parse(item.rawPayload) : item.rawPayload;

    return {
      id: item.id,
      feed_name: 'CRT_SH',
      external_id: item.id.replace(/^crtsh:/, ''),
      title: item.title,
      category: 'CERTIFICATE',
      severity: 'INFO',
      source_url: item.sourceUrl,
      published_at: item.publishedAt || item.retrievedAt,
      ingested_at: item.retrievedAt,
      summary: item.summary,
      payload: JSON.stringify(raw),
      geocoding_lat: null,
      geocoding_lon: null,
      is_synthetic: 0
    };
  }
}
