// server/connectors/usgs.ts
// USGS Earthquakes GeoJSON Feed Connector

import { safeFetch } from '../security/ssrf.js';
import {
  BaseConnector,
  computeCanonicalFingerprint,
  type ConnectorQuery,
  type NormalizedEvidenceItem,
  type RateLimitConfig
} from './base.js';
import type { FeedRecord, FeedSeverity } from '../db/schema.js';

export interface UsgsFeature {
  type: 'Feature';
  id: string;
  geometry: {
    type: 'Point';
    coordinates: [number, number, number]; // [lon, lat, depth_km]
  };
  properties: {
    mag: number | null;
    place: string | null;
    time: number; // epoch ms
    updated?: number;
    tz?: number | null;
    url: string;
    detail?: string;
    felt?: number | null;
    cdi?: number | null;
    mmi?: number | null;
    alert?: 'green' | 'yellow' | 'orange' | 'red' | null;
    status: 'reviewed' | 'automatic';
    tsunami: number; // 0 or 1
    sig: number; // significance score
    net?: string;
    code?: string;
    magType?: string;
    type?: string;
    title?: string;
  };
}

export interface UsgsGeoJsonResponse {
  type: 'FeatureCollection';
  metadata?: {
    generated: number;
    url: string;
    title: string;
    status: number;
    api: string;
    count: number;
  };
  features: UsgsFeature[];
}

export class UsgsEarthquakeConnector extends BaseConnector {
  readonly id = 'usgs_earthquakes';
  readonly name = 'USGS Earthquakes API';
  readonly category = 'geospatial' as const;
  readonly rateLimitConfig: RateLimitConfig = { capacity: 5, refillPerSecond: 1.0 };

  private readonly defaultUrl = 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson';

  /**
   * Calculates operational severity based on USGS alert color, magnitude, and significance.
   */
  public calculateSeverity(feat: UsgsFeature): FeedSeverity {
    const mag = feat.properties.mag ?? 0;
    const alert = feat.properties.alert;
    const sig = feat.properties.sig ?? 0;

    if (alert === 'red' || mag >= 7.0 || sig >= 800) return 'CRITICAL';
    if (alert === 'orange' || mag >= 6.0 || sig >= 600) return 'HIGH';
    if (alert === 'yellow' || mag >= 4.5 || sig >= 300) return 'MEDIUM';
    if (alert === 'green' || mag >= 2.5) return 'LOW';
    return 'INFO';
  }

  public async fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]> {
    const targetUrl = query?.target || this.defaultUrl;

    return await this.executeGuarded(async () => {
      const res = await safeFetch(targetUrl, {
        timeoutMs: 8000,
        headers: { Accept: 'application/geo+json, application/json' }
      });

      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new Error(`USGS HTTP Error ${res.statusCode}: ${res.statusText}`);
      }

      const parsed: UsgsGeoJsonResponse = JSON.parse(res.data);
      if (parsed.type !== 'FeatureCollection' || !Array.isArray(parsed.features)) {
        throw new Error('USGS_INVALID_SCHEMA: Response is not a valid GeoJSON FeatureCollection');
      }

      const items: NormalizedEvidenceItem[] = [];
      const retrievedAt = new Date().toISOString();

      for (const feat of parsed.features) {
        if (!feat.id || !feat.geometry || !Array.isArray(feat.geometry.coordinates)) {
          continue;
        }

        const [lon, lat, depth = 0] = feat.geometry.coordinates;
        const mag = feat.properties.mag ?? 0;
        const place = feat.properties.place || 'Unknown location';
        const pubDate = feat.properties.time ? new Date(feat.properties.time).toISOString() : retrievedAt;
        const severity = this.calculateSeverity(feat);
        const naturalKey = `usgs:${feat.id}`;

        const summary = [
          `Magnitude ${mag.toFixed(1)} earthquake recorded at ${place}.`,
          `Focal depth: ${depth.toFixed(1)} km.`,
          `Alert Level: ${(feat.properties.alert || 'none').toUpperCase()}.`,
          `Significance Index: ${feat.properties.sig ?? 'N/A'}.`,
          `Review Status: ${(feat.properties.status || 'automatic').toUpperCase()}.`,
          feat.properties.tsunami === 1 ? '⚠️ Tsunami advisory issued.' : 'No tsunami advisory.'
        ].join(' ');

        const canonicalPayload = {
          id: feat.id,
          mag,
          place,
          time: pubDate,
          coordinates: [lon, lat, depth],
          severity,
          alert: feat.properties.alert || null,
          url: feat.properties.url
        };

        const contentHash = computeCanonicalFingerprint(canonicalPayload);

        items.push({
          id: naturalKey,
          sourceConnectorId: this.id,
          sourceName: this.name,
          sourceUrl: feat.properties.url || `https://earthquake.usgs.gov/earthquakes/eventpage/${feat.id}`,
          sourceType: 'USGS_EARTHQUAKE',
          feedCategory: 'EARTHQUAKE',
          severity,
          title: feat.properties.title || `M ${mag.toFixed(1)} - ${place}`,
          summary,
          publishedAt: pubDate,
          retrievedAt,
          verificationStatus: 'Observed',
          confidenceScore: feat.properties.status === 'reviewed' ? 1.0 : 0.85,
          contentHash,
          rawPayload: canonicalPayload,
          parsedPayload: canonicalPayload,
          coordinates: { lat, lon, depthKm: depth },
          extractedEntities: [
            {
              type: 'GEOLOCATION',
              value: `${lat.toFixed(4)}, ${lon.toFixed(4)}`,
              attributes: {
                latitude: lat,
                longitude: lon,
                depth_km: depth,
                magnitude: mag,
                place,
                alert: feat.properties.alert
              }
            }
          ]
        });
      }

      this.freshnessTimestamp = parsed.metadata?.generated
        ? new Date(parsed.metadata.generated).toISOString()
        : retrievedAt;

      return items;
    });
  }

  public toFeedRecord(item: NormalizedEvidenceItem): FeedRecord {
    const raw = typeof item.rawPayload === 'string' ? JSON.parse(item.rawPayload) : item.rawPayload;
    const [lon, lat] = raw.coordinates || [null, null];
    const featSeverity: FeedSeverity = raw.severity || 'INFO';

    return {
      id: item.id,
      feed_name: 'USGS',
      external_id: item.id.replace(/^usgs:/, ''),
      title: item.title,
      category: 'EARTHQUAKE',
      severity: featSeverity,
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
