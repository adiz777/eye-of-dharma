// server/connectors/dns_rdap.ts
// Multi-Record DNS, DoH Fallback, and RFC 7483 RDAP Connector

import dns from 'node:dns';
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

export interface DnsRecordResult {
  type: 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME' | 'PTR';
  value: string;
  ttl?: number;
  priority?: number;
}

export interface DnsLookupResult {
  target: string;
  records: DnsRecordResult[];
  resolver: 'native' | 'doh';
  found: boolean;
  error?: string;
}

export interface RdapDomainResult {
  handle: string;
  domainName: string;
  status: string[];
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  lastUpdatedDate?: string;
  nameservers: string[];
  rawPayload: Record<string, unknown>;
}

export interface RdapIpResult {
  handle: string;
  startAddress: string;
  endAddress: string;
  ipVersion: string;
  name?: string;
  country?: string;
  parentHandle?: string;
  rawPayload: Record<string, unknown>;
}

/**
 * Native DNS resolution using node:dns/promises across multiple record types
 */
export async function resolveNativeDns(domain: string): Promise<DnsRecordResult[]> {
  const records: DnsRecordResult[] = [];

  const [aRes, aaaaRes, mxRes, txtRes, nsRes, cnameRes] = await Promise.allSettled([
    dns.promises.resolve4(domain),
    dns.promises.resolve6(domain),
    dns.promises.resolveMx(domain),
    dns.promises.resolveTxt(domain),
    dns.promises.resolveNs(domain),
    dns.promises.resolveCname(domain)
  ]);

  if (aRes.status === 'fulfilled') {
    for (const ip of aRes.value) {
      records.push({ type: 'A', value: ip });
    }
  }

  if (aaaaRes.status === 'fulfilled') {
    for (const ip6 of aaaaRes.value) {
      records.push({ type: 'AAAA', value: ip6 });
    }
  }

  if (mxRes.status === 'fulfilled') {
    for (const mx of mxRes.value) {
      records.push({ type: 'MX', value: mx.exchange, priority: mx.priority });
    }
  }

  if (txtRes.status === 'fulfilled') {
    for (const chunks of txtRes.value) {
      records.push({ type: 'TXT', value: chunks.join('') });
    }
  }

  if (nsRes.status === 'fulfilled') {
    for (const ns of nsRes.value) {
      records.push({ type: 'NS', value: ns });
    }
  }

  if (cnameRes.status === 'fulfilled') {
    for (const cname of cnameRes.value) {
      records.push({ type: 'CNAME', value: cname });
    }
  }

  return records;
}

/**
 * Cloudflare DNS-over-HTTPS (DoH) fallback query
 */
export async function resolveDoh(name: string, type: 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS'): Promise<DnsRecordResult[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await safeFetch(url, {
    timeoutMs: 5000,
    headers: {
      Accept: 'application/dns-json',
      'User-Agent': 'EyeOfDharma-Collector/1.0'
    }
  });

  const parsed = JSON.parse(res.data);
  // Status 3 is NXDOMAIN
  if (parsed.Status === 3 || !parsed.Answer) {
    return [];
  }

  const results: DnsRecordResult[] = [];
  for (const ans of parsed.Answer) {
    let cleanVal = String(ans.data).trim();
    if (cleanVal.endsWith('.')) cleanVal = cleanVal.slice(0, -1);
    if (cleanVal.startsWith('"') && cleanVal.endsWith('"')) cleanVal = cleanVal.slice(1, -1);

    if (type === 'MX') {
      const parts = cleanVal.split(/\s+/);
      const priority = parts.length > 1 ? parseInt(parts[0], 10) : undefined;
      const exchange = parts.length > 1 ? parts[1] : parts[0];
      results.push({ type: 'MX', value: exchange, priority, ttl: ans.TTL });
    } else {
      results.push({ type, value: cleanVal, ttl: ans.TTL });
    }
  }

  return results;
}

/**
 * Full DNS query coordinator with native resolution and DoH fallback
 */
export async function resolveDnsWithFallback(domain: string): Promise<DnsLookupResult> {
  try {
    const nativeRecords = await resolveNativeDns(domain);
    if (nativeRecords.length > 0) {
      return { target: domain, records: nativeRecords, resolver: 'native', found: true };
    }
  } catch {
    // Native resolution threw unexpected network error, attempt DoH
  }

  // Fallback to Cloudflare DoH
  try {
    const dohPromises = await Promise.allSettled([
      resolveDoh(domain, 'A'),
      resolveDoh(domain, 'AAAA'),
      resolveDoh(domain, 'MX'),
      resolveDoh(domain, 'TXT'),
      resolveDoh(domain, 'NS')
    ]);

    const dohRecords: DnsRecordResult[] = [];
    for (const r of dohPromises) {
      if (r.status === 'fulfilled') {
        dohRecords.push(...r.value);
      }
    }

    return {
      target: domain,
      records: dohRecords,
      resolver: 'doh',
      found: dohRecords.length > 0
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      target: domain,
      records: [],
      resolver: 'doh',
      found: false,
      error: msg
    };
  }
}

/**
 * Parse RFC 7095 jCard vcardArray to extract formatted entity name
 */
export function extractVCardName(vcardArray: unknown): string | null {
  if (!Array.isArray(vcardArray) || vcardArray.length < 2 || !Array.isArray(vcardArray[1])) {
    return null;
  }
  const properties = vcardArray[1];
  for (const prop of properties) {
    if (Array.isArray(prop) && prop[0] === 'fn' && typeof prop[3] === 'string') {
      return prop[3];
    }
  }
  return null;
}

/**
 * RFC 7483 RDAP Domain Query
 */
export async function queryRdapDomain(domain: string): Promise<{ found: boolean; data?: RdapDomainResult; error?: string }> {
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  try {
    const res = await safeFetch(url, {
      timeoutMs: 5000,
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'EyeOfDharma-Collector/1.0'
      }
    });

    if (res.statusCode === 404) {
      // Confirmed negative result: domain not registered
      return { found: false };
    }

    if (res.statusCode !== 200) {
      return { found: false, error: `RDAP_HTTP_${res.statusCode}` };
    }

    const payload = JSON.parse(res.data);
    let registrar: string | undefined;

    if (Array.isArray(payload.entities)) {
      for (const ent of payload.entities) {
        if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
          registrar = extractVCardName(ent.vcardArray) || ent.handle;
          break;
        }
      }
    }

    let registrationDate: string | undefined;
    let expirationDate: string | undefined;
    let lastUpdatedDate: string | undefined;

    if (Array.isArray(payload.events)) {
      for (const ev of payload.events) {
        if (ev.eventAction === 'registration') registrationDate = ev.eventDate;
        else if (ev.eventAction === 'expiration') expirationDate = ev.eventDate;
        else if (ev.eventAction === 'last changed' || ev.eventAction === 'last update') lastUpdatedDate = ev.eventDate;
      }
    }

    const nameservers: string[] = [];
    if (Array.isArray(payload.nameservers)) {
      for (const ns of payload.nameservers) {
        if (ns.ldhName) nameservers.push(ns.ldhName);
      }
    }

    return {
      found: true,
      data: {
        handle: payload.handle || domain,
        domainName: payload.ldhName || domain,
        status: Array.isArray(payload.status) ? payload.status : [],
        registrar,
        registrationDate,
        expirationDate,
        lastUpdatedDate,
        nameservers,
        rawPayload: payload
      }
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { found: false, error: msg };
  }
}

/**
 * RFC 7483 RDAP IP Query
 */
export async function queryRdapIp(ip: string): Promise<{ found: boolean; data?: RdapIpResult; error?: string }> {
  const url = `https://rdap.org/ip/${encodeURIComponent(ip)}`;
  try {
    const res = await safeFetch(url, {
      timeoutMs: 5000,
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'EyeOfDharma-Collector/1.0'
      }
    });

    if (res.statusCode === 404) {
      return { found: false };
    }

    const payload = JSON.parse(res.data);
    return {
      found: true,
      data: {
        handle: payload.handle || ip,
        startAddress: payload.startAddress || ip,
        endAddress: payload.endAddress || ip,
        ipVersion: payload.ipVersion || (ip.includes(':') ? 'v6' : 'v4'),
        name: payload.name,
        country: payload.country,
        parentHandle: payload.parentHandle,
        rawPayload: payload
      }
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { found: false, error: msg };
  }
}

export class DnsRdapConnector extends BaseConnector {
  public readonly id = 'DNS_RDAP';
  public readonly name = 'DNS & RDAP Network Resolver';
  public readonly category = 'infrastructure' as const;
  public readonly rateLimitConfig: RateLimitConfig = { capacity: 10, refillPerSecond: 5 };

  public async fetch(query?: ConnectorQuery): Promise<NormalizedEvidenceItem[]> {
    const target = query?.target?.trim();
    if (!target) {
      return [];
    }

    const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target) || target.includes(':');
    const items: NormalizedEvidenceItem[] = [];
    const retrievedAt = new Date().toISOString();

    return await this.executeGuarded(async () => {
      if (!isIp) {
        // 1. Resolve DNS
        const dnsResult = await resolveDnsWithFallback(target);
        if (dnsResult.records.length > 0) {
          const hash = computeCanonicalFingerprint(dnsResult);
          const entities: ExtractedEntity[] = dnsResult.records
            .filter((r) => r.type === 'A' || r.type === 'AAAA')
            .map((r) => ({ type: 'IP_ADDRESS', value: r.value }));

          items.push({
            id: `dns:${target}:resolved:${hash.slice(0, 16)}`,
            sourceConnectorId: this.id,
            sourceName: this.name,
            sourceUrl: `dns://${target}`,
            sourceType: 'DNS_RECORD',
            feedCategory: 'THREAT_INTEL',
            severity: 'INFO',
            title: `DNS Resolution: ${target}`,
            summary: `Resolved ${dnsResult.records.length} records via ${dnsResult.resolver}`,
            publishedAt: null,
            retrievedAt,
            verificationStatus: 'Observed',
            confidenceScore: 0.98,
            contentHash: hash,
            rawPayload: dnsResult as unknown as Record<string, unknown>,
            parsedPayload: dnsResult as unknown as Record<string, unknown>,
            extractedEntities: entities
          });
        }

        // 2. Query RDAP Domain
        const rdapResult = await queryRdapDomain(target);
        if (rdapResult.found && rdapResult.data) {
          const d = rdapResult.data;
          const hash = computeCanonicalFingerprint(d);
          const entities: ExtractedEntity[] = [{ type: 'DOMAIN', value: target }];
          if (d.registrar) {
            entities.push({ type: 'ORGANIZATION', value: d.registrar });
          }

          items.push({
            id: `rdap:${target}:${hash.slice(0, 16)}`,
            sourceConnectorId: this.id,
            sourceName: this.name,
            sourceUrl: `https://rdap.org/domain/${encodeURIComponent(target)}`,
            sourceType: 'RDAP_REGISTRATION',
            feedCategory: 'THREAT_INTEL',
            severity: 'INFO',
            title: `RDAP Registration: ${target}`,
            summary: `Registrar: ${d.registrar || 'Unknown'}. Created: ${d.registrationDate || 'N/A'}. Expires: ${d.expirationDate || 'N/A'}`,
            publishedAt: d.registrationDate || null,
            retrievedAt,
            verificationStatus: 'Observed',
            confidenceScore: 0.95,
            contentHash: hash,
            rawPayload: d.rawPayload,
            parsedPayload: d as unknown as Record<string, unknown>,
            extractedEntities: entities
          });
        }
      } else {
        // Query RDAP IP
        const rdapIpResult = await queryRdapIp(target);
        if (rdapIpResult.found && rdapIpResult.data) {
          const d = rdapIpResult.data;
          const hash = computeCanonicalFingerprint(d);

          items.push({
            id: `rdap_ip:${target}:${hash.slice(0, 16)}`,
            sourceConnectorId: this.id,
            sourceName: this.name,
            sourceUrl: `https://rdap.org/ip/${encodeURIComponent(target)}`,
            sourceType: 'RDAP_REGISTRATION',
            feedCategory: 'THREAT_INTEL',
            severity: 'INFO',
            title: `RDAP IP Network: ${target}`,
            summary: `Network: ${d.name || d.handle} (${d.startAddress} - ${d.endAddress}). Country: ${d.country || 'N/A'}`,
            publishedAt: null,
            retrievedAt,
            verificationStatus: 'Observed',
            confidenceScore: 0.95,
            contentHash: hash,
            rawPayload: d.rawPayload,
            parsedPayload: d as unknown as Record<string, unknown>,
            extractedEntities: [{ type: 'IP_ADDRESS', value: target }]
          });
        }
      }

      this.freshnessTimestamp = retrievedAt;
      return items;
    });
  }

  public toFeedRecord(item: NormalizedEvidenceItem): FeedRecord {
    const raw = typeof item.rawPayload === 'string' ? JSON.parse(item.rawPayload) : item.rawPayload;

    return {
      id: item.id,
      feed_name: 'DNS_RDAP',
      external_id: item.id,
      title: item.title,
      category: 'THREAT_INTEL',
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
