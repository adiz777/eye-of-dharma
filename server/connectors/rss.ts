// server/connectors/rss.ts
// Generic RSS 2.0 & Atom 1.0 XML Feed Parser Connector with HTML & Script Sanitization

import crypto from 'node:crypto';
import { safeFetch } from '../security/ssrf.js';
import { extractXmlTag, extractXmlAttr, sanitizeToPlainText, sanitizeSafeHtml, assertSafeXml } from './xml_sanitizer.js';
import {
  BaseConnector,
  computeCanonicalFingerprint,
  type ConnectorQuery,
  type NormalizedEvidenceItem,
  type RateLimitConfig
} from './base.js';
import type { FeedRecord, FeedSeverity } from '../db/schema.js';

export class RssFeedConnector extends BaseConnector {
  readonly id = 'rss_feed';
  readonly name = 'Public RSS/Atom Intelligence Feeds';
  readonly category = 'news' as const;
  readonly rateLimitConfig: RateLimitConfig = { capacity: 5, refillPerSecond: 1.0 };

  public readonly defaultFeedUrl = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';

  /**
   * Parses arbitrary RSS 2.0 or Atom 1.0 XML string into normalized evidence items.
   */
  public async parseFeedXml(xmlData: string, feedUrl: string): Promise<NormalizedEvidenceItem[]> {
    assertSafeXml(xmlData);

    const isAtom = /<feed\b[^>]*xmlns=['"]http:\/\/www\.w3\.org\/2005\/Atom['"]/i.test(xmlData) ||
                   /<feed\b[^>]*>/i.test(xmlData);

    const retrievedAt = new Date().toISOString();
    const items: NormalizedEvidenceItem[] = [];

    const channelTitle = extractXmlTag(xmlData, 'title') || 'Public Intelligence Feed';

    if (isAtom) {
      // Atom 1.0 Processing: <entry>...</entry>
      const entryMatches = xmlData.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];

      for (const entryXml of entryMatches) {
        const rawTitle = extractXmlTag(entryXml, 'title') || 'Untitled';
        const rawId = extractXmlTag(entryXml, 'id') || '';
        const rawPublished = extractXmlTag(entryXml, 'published') || extractXmlTag(entryXml, 'updated') || '';
        const rawContent = extractXmlTag(entryXml, 'content') || extractXmlTag(entryXml, 'summary') || '';

        let link = extractXmlAttr(entryXml, 'link', 'href');
        if (!link) {
          link = extractXmlTag(entryXml, 'link') || feedUrl;
        }

        const title = sanitizeToPlainText(rawTitle);
        const plainSummary = sanitizeToPlainText(rawContent);
        const safeHtml = sanitizeSafeHtml(rawContent);

        let pubDate = retrievedAt;
        if (rawPublished) {
          try {
            pubDate = new Date(rawPublished).toISOString();
          } catch {
            pubDate = retrievedAt;
          }
        }

        const hashInput = `${rawId || link || title}_${pubDate}`;
        const naturalKey = `rss:${crypto.createHash('sha256').update(hashInput).digest('hex').substring(0, 16)}`;

        const canonicalPayload = {
          title,
          link,
          id: rawId,
          pubDate,
          summary: plainSummary,
          html: safeHtml
        };

        const contentHash = computeCanonicalFingerprint(canonicalPayload);

        items.push({
          id: naturalKey,
          sourceConnectorId: this.id,
          sourceName: sanitizeToPlainText(channelTitle),
          sourceUrl: link,
          sourceType: 'RSS_FEED',
          feedCategory: 'NEWS',
          severity: /critical|zero-day|exploit|emergency/i.test(title) ? 'HIGH' : 'INFO',
          title,
          summary: plainSummary,
          publishedAt: pubDate,
          retrievedAt,
          verificationStatus: 'Source-reported',
          confidenceScore: 0.70,
          contentHash,
          rawPayload: canonicalPayload,
          parsedPayload: canonicalPayload,
          extractedEntities: this.extractIocs(`${title} ${plainSummary}`)
        });
      }
    } else {
      // RSS 2.0 Processing: <item>...</item>
      const itemMatches = xmlData.match(/<item\b[\s\S]*?<\/item>/gi) || [];

      for (const itemXml of itemMatches) {
        const rawTitle = extractXmlTag(itemXml, 'title') || 'Untitled';
        const rawLink = extractXmlTag(itemXml, 'link') || feedUrl;
        const rawDesc = extractXmlTag(itemXml, 'description') || extractXmlTag(itemXml, 'content:encoded') || '';
        const rawPubDate = extractXmlTag(itemXml, 'pubDate') || '';
        const guid = extractXmlTag(itemXml, 'guid') || rawLink;

        const title = sanitizeToPlainText(rawTitle);
        const plainSummary = sanitizeToPlainText(rawDesc);
        const safeHtml = sanitizeSafeHtml(rawDesc);

        let pubDate = retrievedAt;
        if (rawPubDate) {
          try {
            pubDate = new Date(rawPubDate).toISOString();
          } catch {
            pubDate = retrievedAt;
          }
        }

        const hashInput = `${guid || rawLink || title}_${pubDate}`;
        const naturalKey = `rss:${crypto.createHash('sha256').update(hashInput).digest('hex').substring(0, 16)}`;

        const canonicalPayload = {
          title,
          link: rawLink,
          guid,
          pubDate,
          summary: plainSummary,
          html: safeHtml
        };

        const contentHash = computeCanonicalFingerprint(canonicalPayload);

        items.push({
          id: naturalKey,
          sourceConnectorId: this.id,
          sourceName: sanitizeToPlainText(channelTitle),
          sourceUrl: rawLink,
          sourceType: 'RSS_FEED',
          feedCategory: 'NEWS',
          severity: /critical|zero-day|exploit|emergency/i.test(title) ? 'HIGH' : 'INFO',
          title,
          summary: plainSummary,
          publishedAt: pubDate,
          retrievedAt,
          verificationStatus: 'Source-reported',
          confidenceScore: 0.70,
          contentHash,
          rawPayload: canonicalPayload,
          parsedPayload: canonicalPayload,
          extractedEntities: this.extractIocs(`${title} ${plainSummary}`)
        });
      }
    }

    return items;
  }

  private extractIocs(text: string): Array<{ type: string; value: string }> {
    const results: Array<{ type: string; value: string }> = [];

    // CVEs
    const cves = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
    for (const cve of Array.from(new Set(cves))) {
      results.push({ type: 'VULNERABILITY', value: cve.toUpperCase() });
    }

    // IPv4 addresses (excluding private ranges)
    const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    for (const ip of Array.from(new Set(ips))) {
      if (!/^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)/.test(ip)) {
        results.push({ type: 'IP_ADDRESS', value: ip });
      }
    }

    return results;
  }

  public async fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]> {
    const targetUrl = query?.target || this.defaultFeedUrl;

    return await this.executeGuarded(async () => {
      const res = await safeFetch(targetUrl, {
        timeoutMs: 10000,
        headers: { Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' }
      });

      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new Error(`RSS HTTP Error ${res.statusCode}: ${res.statusText}`);
      }

      const items = await this.parseFeedXml(res.data, targetUrl);
      this.freshnessTimestamp = new Date().toISOString();
      return items;
    });
  }

  public toFeedRecord(item: NormalizedEvidenceItem): FeedRecord {
    const raw = typeof item.rawPayload === 'string' ? JSON.parse(item.rawPayload) : item.rawPayload;
    const severity: FeedSeverity = item.severity;

    return {
      id: item.id,
      feed_name: 'RSS',
      external_id: item.id.replace(/^rss:/, ''),
      title: item.title,
      category: 'NEWS',
      severity,
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
