// server/connectors/cisa.ts
// CISA Known Exploited Vulnerabilities (KEV) Catalog & Cybersecurity Advisories Connector

import crypto from 'node:crypto';
import { safeFetch } from '../security/ssrf.js';
import { extractXmlTag, sanitizeToPlainText, assertSafeXml } from './xml_sanitizer.js';
import {
  BaseConnector,
  computeCanonicalFingerprint,
  type ConnectorQuery,
  type NormalizedEvidenceItem,
  type RateLimitConfig
} from './base.js';
import type { FeedRecord, FeedSeverity } from '../db/schema.js';

export interface KevVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string; // YYYY-MM-DD
  shortDescription: string;
  requiredAction: string;
  dueDate: string; // YYYY-MM-DD
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notes?: string;
  cwes: string[];
}

export interface KevCatalogResponse {
  title?: string;
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities: KevVulnerability[];
}

export class CisaConnector extends BaseConnector {
  readonly id = 'cisa_intel';
  readonly name = 'CISA Cybersecurity Feeds';
  readonly category = 'threat_intel' as const;
  readonly rateLimitConfig: RateLimitConfig = { capacity: 2, refillPerSecond: 0.2 };

  readonly kevCatalogUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  readonly advisoriesRssUrl = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';

  /**
   * Fetches and normalizes CISA KEV Catalog items.
   * Explicitly sets maxBytes = 25MB to accommodate growing vulnerability list.
   */
  public async fetchKevCatalog(targetUrl = this.kevCatalogUrl): Promise<NormalizedEvidenceItem[]> {
    return await this.executeGuarded(async () => {
      const res = await safeFetch(targetUrl, {
        timeoutMs: 15000,
        maxBytes: 25 * 1024 * 1024, // 25 MB payload allowance
        headers: { Accept: 'application/json' }
      });

      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new Error(`CISA KEV HTTP Error ${res.statusCode}: ${res.statusText}`);
      }

      const parsed: KevCatalogResponse = JSON.parse(res.data);
      if (!Array.isArray(parsed.vulnerabilities)) {
        throw new Error('CISA_KEV_INVALID_SCHEMA: Missing vulnerabilities array in KEV response');
      }

      const items: NormalizedEvidenceItem[] = [];
      const retrievedAt = new Date().toISOString();

      for (const v of parsed.vulnerabilities) {
        if (!v.cveID) continue;

        const isRansomware = v.knownRansomwareCampaignUse === 'Known';
        const severity: FeedSeverity = isRansomware ? 'CRITICAL' : 'HIGH';
        const naturalKey = `cisa_kev:${v.cveID}`;
        const pubDate = v.dateAdded ? `${v.dateAdded}T00:00:00.000Z` : retrievedAt;

        const summary = [
          `Vulnerability: ${v.vulnerabilityName}.`,
          `Vendor/Product: ${v.vendorProject} ${v.product}.`,
          `CWEs: ${(v.cwes || []).join(', ') || 'N/A'}.`,
          `Ransomware Campaign Use: ${v.knownRansomwareCampaignUse}.`,
          `Action Required: ${v.requiredAction}.`,
          `Remediation Due: ${v.dueDate}.`,
          v.shortDescription
        ].join(' ');

        const canonicalPayload = {
          cveID: v.cveID,
          vendorProject: v.vendorProject,
          product: v.product,
          vulnerabilityName: v.vulnerabilityName,
          dateAdded: v.dateAdded,
          dueDate: v.dueDate,
          knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
          cwes: v.cwes || [],
          notes: v.notes || null
        };

        const contentHash = computeCanonicalFingerprint(canonicalPayload);

        const sourceUrl = (v.notes && /^https?:\/\//i.test(v.notes))
          ? v.notes
          : `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${v.cveID}`;

        items.push({
          id: naturalKey,
          sourceConnectorId: 'cisa_kev',
          sourceName: 'CISA Known Exploited Vulnerabilities Catalog',
          sourceUrl,
          sourceType: 'CISA_KEV',
          feedCategory: 'VULNERABILITY',
          severity,
          title: `${v.cveID} - ${v.vendorProject} ${v.product}: ${v.vulnerabilityName}`,
          summary,
          publishedAt: pubDate,
          retrievedAt,
          verificationStatus: 'Source-reported',
          confidenceScore: 1.0,
          contentHash,
          rawPayload: canonicalPayload,
          parsedPayload: canonicalPayload,
          extractedEntities: [
            {
              type: 'VULNERABILITY',
              value: v.cveID,
              attributes: {
                vendor: v.vendorProject,
                product: v.product,
                cwes: v.cwes,
                ransomware: isRansomware,
                dueDate: v.dueDate
              }
            },
            {
              type: 'DOMAIN',
              value: v.vendorProject.toLowerCase().replace(/[^a-z0-9.-]/g, '') + '.com',
              attributes: { role: 'vendor' }
            }
          ]
        });
      }

      this.freshnessTimestamp = retrievedAt;
      return items;
    });
  }

  /**
   * Fetches and parses CISA Cybersecurity Advisories RSS feed.
   */
  public async fetchAdvisoriesRss(targetUrl = this.advisoriesRssUrl): Promise<NormalizedEvidenceItem[]> {
    return await this.executeGuarded(async () => {
      const res = await safeFetch(targetUrl, {
        timeoutMs: 10000,
        headers: { Accept: 'application/rss+xml, application/xml, text/xml' }
      });

      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new Error(`CISA Advisories HTTP Error ${res.statusCode}: ${res.statusText}`);
      }

      assertSafeXml(res.data);

      const items: NormalizedEvidenceItem[] = [];
      const retrievedAt = new Date().toISOString();

      // Extract <item> elements
      const itemMatches = res.data.match(/<item\b[\s\S]*?<\/item>/gi) || [];

      for (const itemXml of itemMatches) {
        const rawTitle = extractXmlTag(itemXml, 'title') || 'Untitled Advisory';
        const rawLink = extractXmlTag(itemXml, 'link') || '';
        const rawDesc = extractXmlTag(itemXml, 'description') || '';
        const rawPubDate = extractXmlTag(itemXml, 'pubDate') || '';
        const guid = extractXmlTag(itemXml, 'guid') || rawLink;

        const title = sanitizeToPlainText(rawTitle);
        const summary = sanitizeToPlainText(rawDesc);
        const pubDate = rawPubDate ? new Date(rawPubDate).toISOString() : retrievedAt;

        // Severity heuristic from advisory title & summary
        const combinedLower = `${title} ${summary}`.toLowerCase();
        let severity: FeedSeverity = 'MEDIUM';
        if (/emergency directive|zero-day|critical|actively exploited/i.test(combinedLower)) {
          severity = 'CRITICAL';
        } else if (/ransomware|high severity|malware/i.test(combinedLower)) {
          severity = 'HIGH';
        }

        const csafLink = (summary.match(/https?:\/\/[^\s"]+\.json/i) || [])[0] || null;

        const canonicalPayload = {
          title,
          link: rawLink,
          guid,
          pubDate,
          summary,
          csafLink,
          severity
        };

        const contentHash = computeCanonicalFingerprint(canonicalPayload);
        const guidHash = crypto.createHash('sha256').update(guid || rawLink || title).digest('hex').substring(0, 16);
        const naturalKey = `cisa_adv:${guidHash}`;

        // Extract referenced CVEs
        const cveMatches = Array.from(new Set(combinedLower.match(/cve-\d{4}-\d{4,7}/gi) || [])).map(c => c.toUpperCase());

        items.push({
          id: naturalKey,
          sourceConnectorId: 'cisa_advisories',
          sourceName: 'CISA Cybersecurity Advisories',
          sourceUrl: rawLink || this.advisoriesRssUrl,
          sourceType: 'CISA_ADVISORY',
          feedCategory: 'ADVISORY',
          severity,
          title,
          summary,
          publishedAt: pubDate,
          retrievedAt,
          verificationStatus: 'Source-reported',
          confidenceScore: 0.95,
          contentHash,
          rawPayload: canonicalPayload,
          parsedPayload: canonicalPayload,
          extractedEntities: cveMatches.map((cve) => ({
            type: 'VULNERABILITY',
            value: cve
          }))
        });
      }

      this.freshnessTimestamp = retrievedAt;
      return items;
    });
  }

  public async fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]> {
    const mode = query?.category?.toUpperCase() === 'ADVISORY' || query?.category?.toUpperCase() === 'CISA_ALERTS'
      ? 'advisories'
      : 'kev';

    if (mode === 'advisories') {
      return await this.fetchAdvisoriesRss(query?.target);
    } else {
      return await this.fetchKevCatalog(query?.target);
    }
  }

  public toFeedRecord(item: NormalizedEvidenceItem): FeedRecord {
    const raw = typeof item.rawPayload === 'string' ? JSON.parse(item.rawPayload) : item.rawPayload;
    const isKev = item.sourceConnectorId === 'cisa_kev';

    return {
      id: item.id,
      feed_name: isKev ? 'CISA_KEV' : 'CISA_ALERTS',
      external_id: isKev ? raw.cveID : raw.guid,
      title: item.title,
      category: isKev ? 'VULNERABILITY' : 'ADVISORY',
      severity: isKev
        ? (raw.knownRansomwareCampaignUse === 'Known' ? 'CRITICAL' : 'HIGH')
        : (raw.severity || 'MEDIUM'),
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
