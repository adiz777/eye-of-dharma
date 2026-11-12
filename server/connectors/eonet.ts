// server/connectors/eonet.ts
// NASA EONET v3 Natural Hazard Events API Connector

import { safeFetch } from '../security/ssrf.js';
import {
  BaseConnector,
  computeCanonicalFingerprint,
  type ConnectorQuery,
  type NormalizedEvidenceItem,
  type RateLimitConfig
} from './base.js';
import type { FeedRecord, FeedCategory, FeedSeverity } from '../db/schema.js';

export interface EonetCategory {
  id: string;
  title: string;
}

export interface EonetSource {
  id: string;
  url: string;
}

export interface EonetGeometry {
  magnitudeValue?: number | null;
  magnitudeUnit?: string | null;
  date: string; // ISO 8601
  type: 'Point' | 'Polygon' | string;
  coordinates: [number, number] | number[][][] | unknown; // Point: [lon, lat]
}

export interface EonetEvent {
  id: string; // e.g. "EONET_25728"
  title: string;
  description: string | null;
  link?: string;
  closed: string | null;
  categories: EonetCategory[];
  sources: EonetSource[];
  geometry: EonetGeometry[];
}

export interface EonetResponse {
  title?: string;
  description?: string;
  link?: string;
  events: EonetEvent[];
}

export class NasaEonetConnector extends BaseConnector {
  readonly id = 'nasa_eonet';
  readonly name = 'NASA EONET v3';
  readonly category = 'geospatial' as const;
  readonly rateLimitConfig: RateLimitConfig = { capacity: 3, refillPerSecond: 0.5 };

  private readonly defaultUrl = 'https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit=100';

  public mapCategory(catId?: string): FeedCategory {
    if (catId === 'earthquakes') return 'EARTHQUAKE';
    return 'HAZARD';
  }

  public calculateSeverity(event: EonetEvent, latestGeo?: EonetGeometry): FeedSeverity {
    if (event.closed !== null) return 'LOW';

    const cat = event.categories?.[0]?.id;
    const mag = latestGeo?.magnitudeValue;

    if (cat === 'severeStorms') {
      if (mag && mag >= 100) return 'CRITICAL'; // Category 3+ hurricane / typhoon
      if (mag && mag >= 64) return 'HIGH';      // Category 1 hurricane / gale
      return 'MEDIUM';
    }

    if (cat === 'wildfires' || cat === 'volcanoes') return 'HIGH';
    if (cat === 'floods' || cat === 'landslides') return 'MEDIUM';
    return 'LOW';
  }

  public async fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]> {
    const targetUrl = query?.target || this.defaultUrl;

    return await this.executeGuarded(async () => {
      const res = await safeFetch(targetUrl, {
        timeoutMs: 10000,
        headers: { Accept: 'application/json' }
      });

      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new Error(`NASA EONET HTTP Error ${res.statusCode}: ${res.statusText}`);
      }

      const parsed: EonetResponse = JSON.parse(res.data);
      if (!Array.isArray(parsed.events)) {
        throw new Error('EONET_INVALID_SCHEMA: Response is missing events array');
      }

      const items: NormalizedEvidenceItem[] = [];
      const retrievedAt = new Date().toISOString();

      for (const ev of parsed.events) {
        if (!ev.id || !ev.geometry || ev.geometry.length === 0) continue;

        // Sort geometry tracking points chronologically ascending
        const sortedPoints = [...ev.geometry].sort(
          (a, b) => new Date(a.date).getTime() - new Date(b.date).getTime()
        );
        const latestPoint = sortedPoints[sortedPoints.length - 1];

        let lon: number | null = null;
        let lat: number | null = null;

        if (latestPoint.type === 'Point' && Array.isArray(latestPoint.coordinates)) {
          lon = Number(latestPoint.coordinates[0]);
          lat = Number(latestPoint.coordinates[1]);
        }

        const primaryCat = ev.categories?.[0]?.id || 'hazard';
        const severity = this.calculateSeverity(ev, latestPoint);
        const naturalKey = `eonet:${ev.id}`;
        const sourceUrl = ev.sources?.[0]?.url || ev.link || `https://eonet.gsfc.nasa.gov/api/v3/events/${ev.id}`;
        const pubDate = latestPoint.date || retrievedAt;
        const feedCat = this.mapCategory(primaryCat);

        const summary = [
          `Hazard: ${ev.title}.`,
          `Category: ${(ev.categories || []).map((c) => c.title).join(', ')}.`,
          `Status: ${ev.closed ? 'CLOSED' : 'ACTIVE'}.`,
          latestPoint.magnitudeValue ? `Current Intensity: ${latestPoint.magnitudeValue} ${latestPoint.magnitudeUnit || ''}.` : '',
          `Tracking points recorded: ${sortedPoints.length}.`
        ].filter(Boolean).join(' ');

        const canonicalPayload = {
          id: ev.id,
          title: ev.title,
          category: primaryCat,
          status: ev.closed ? 'closed' : 'open',
          coordinates: lon !== null && lat !== null ? [lon, lat] : null,
          magnitude: latestPoint.magnitudeValue || null,
          unit: latestPoint.magnitudeUnit || null,
          trackingPointsCount: sortedPoints.length,
          lastObservedAt: pubDate
        };

        const contentHash = computeCanonicalFingerprint(canonicalPayload);

        items.push({
          id: naturalKey,
          sourceConnectorId: this.id,
          sourceName: this.name,
          sourceUrl,
          sourceType: 'NASA_EONET',
          feedCategory: feedCat,
          severity,
          title: ev.title,
          summary,
          publishedAt: pubDate,
          retrievedAt,
          verificationStatus: 'Source-reported',
          confidenceScore: 0.90,
          contentHash,
          rawPayload: canonicalPayload,
          parsedPayload: canonicalPayload,
          coordinates: lat !== null && lon !== null ? { lat, lon } : null,
          extractedEntities: lat !== null && lon !== null ? [
            {
              type: 'GEOLOCATION',
              value: `${lat.toFixed(4)}, ${lon.toFixed(4)}`,
              attributes: {
                latitude: lat,
                longitude: lon,
                hazard_id: ev.id,
                category: primaryCat,
                title: ev.title
              }
            }
          ] : []
        });
      }

      this.freshnessTimestamp = retrievedAt;
      return items;
    });
  }

  public toFeedRecord(item: NormalizedEvidenceItem): FeedRecord {
    const raw = typeof item.rawPayload === 'string' ? JSON.parse(item.rawPayload) : item.rawPayload;
    const [lon, lat] = raw.coordinates || [null, null];
    const category: FeedCategory = this.mapCategory(raw.category);
    const severity: FeedSeverity = item.severity;

    return {
      id: item.id,
      feed_name: 'NASA_EONET',
      external_id: item.id.replace(/^eonet:/, ''),
      title: item.title,
      category,
      severity,
      source_url: item.sourceUrl,
      published_at: item.publishedAt || item.retrievedAt,
      ingested_at: item.retrievedAt,
      summary: item.summary,
      payload: JSON.stringify(raw),
      geocoding_lat: lat,
      geocoding_lon: lon,
      is_synthetic: 0
    };
  }
}
