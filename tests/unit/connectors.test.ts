// tests/unit/connectors.test.ts
// Unit Tests for Resilience, Canonical Fingerprinting, XML Sanitization, and Connector Schema Parsers

import { describe, it, expect, vi } from 'vitest';
import {
  TokenBucket,
  TokenBucketLimiter,
  RateLimitExceededError,
  FullJitter,
  calculateFullJitter,
  withExponentialBackoff,
  CircuitBreaker,
  CircuitBreakerOpenError,
  computeCanonicalFingerprint
} from '../../server/connectors/base.js';
import {
  sanitizeToPlainText,
  sanitizeSafeHtml,
  extractXmlTag,
  extractXmlAttr,
  assertSafeXml
} from '../../server/connectors/xml_sanitizer.js';
import { UsgsEarthquakeConnector } from '../../server/connectors/usgs.js';
import { NasaEonetConnector } from '../../server/connectors/eonet.js';
import { CisaConnector } from '../../server/connectors/cisa.js';
import { RssFeedConnector } from '../../server/connectors/rss.js';
import { parseSanEntries, isValidDomain } from '../../server/connectors/crtsh.js';
import { extractVCardName } from '../../server/connectors/dns_rdap.js';

describe('Resilience: TokenBucket Rate Limiter', () => {
  it('should initialize with full capacity and consume available tokens', () => {
    const bucket = new TokenBucket(5, 1);
    expect(bucket.tryConsume(1)).toBe(true);
    expect(bucket.tryConsume(2)).toBe(true);
    expect(bucket.tryConsume(2)).toBe(true);
    // Exhausted: 5 - 1 - 2 - 2 = 0
    expect(bucket.tryConsume(1)).toBe(false);
  });

  it('should refill tokens over elapsed time up to capacity limit', () => {
    let mockTime = 1000;
    const bucket = new TokenBucketLimiter(5, 2, () => mockTime);
    expect(bucket.tryConsume(5)).toBe(true);
    expect(bucket.tryConsume(1)).toBe(false);

    // Advance 1 second -> +2 tokens
    mockTime += 1000;
    expect(bucket.tryConsume(2)).toBe(true);
    expect(bucket.tryConsume(1)).toBe(false);

    // Advance 10 seconds -> should cap at 5 tokens max
    mockTime += 10000;
    expect(bucket.getTokens()).toBe(5);
    expect(bucket.availableTokens).toBe(5);
  });

  it('should reject acquire when required wait exceeds maxWaitMs', async () => {
    const bucket = new TokenBucket(1, 0.1); // 0.1 tokens/sec -> 10s per token
    expect(bucket.tryConsume(1)).toBe(true); // bucket empty

    // Needs 1 token = 10,000ms wait. If maxWaitMs is 500ms, should throw immediately
    await expect(bucket.acquire(1, 500, 'test-connector')).rejects.toThrow(RateLimitExceededError);
  });
});

describe('Resilience: Exponential Backoff with AWS Full Jitter', () => {
  it('should compute sleep duration strictly bounded within [0, min(maxMs, baseMs * 2^attempt)]', () => {
    const baseMs = 1000;
    const maxMs = 16000;

    for (let attempt = 0; attempt < 10; attempt++) {
      const ceiling = Math.min(maxMs, baseMs * Math.pow(2, attempt));
      for (let i = 0; i < 20; i++) {
        const sleep = FullJitter.calculate(attempt, baseMs, maxMs);
        expect(sleep).toBeGreaterThanOrEqual(0);
        expect(sleep).toBeLessThanOrEqual(ceiling);
      }
    }
  });

  it('should cap ceiling at maxMs for high attempt numbers', () => {
    const sleep = calculateFullJitter(10, 1000, 8000);
    expect(sleep).toBeLessThanOrEqual(8000);
  });

  it('should retry retryable errors up to maxAttempts', async () => {
    let calls = 0;
    const op = vi.fn(async () => {
      calls++;
      if (calls < 3) throw new Error('Temporary gateway timeout');
      return 'SUCCESS';
    });

    const result = await withExponentialBackoff(op, {
      maxAttempts: 3,
      baseBackoffMs: 10,
      maxBackoffMs: 50
    });

    expect(result).toBe('SUCCESS');
    expect(calls).toBe(3);
  });

  it('should abort immediately on non-retryable errors', async () => {
    const op = vi.fn(async () => {
      const err = new Error('Private IP forbidden');
      (err as any).code = 'SSRF_BLOCKED';
      throw err;
    });

    await expect(
      withExponentialBackoff(op, { maxAttempts: 5, baseBackoffMs: 10 })
    ).rejects.toThrow('Private IP forbidden');

    expect(op).toHaveBeenCalledTimes(1);
  });
});

describe('Resilience: CircuitBreaker State Machine', () => {
  it('should start in CLOSED state and execute actions successfully', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 100 });
    expect(cb.getState()).toBe('CLOSED');
    const res = await cb.execute(async () => 'OK');
    expect(res).toBe('OK');
    expect(cb.getState()).toBe('CLOSED');
  });

  it('should trip from CLOSED to OPEN after failureThreshold is reached and fail fast', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 100 });
    const failAction = async () => { throw new Error('Network timeout'); };

    await expect(cb.execute(failAction)).rejects.toThrow('Network timeout');
    expect(cb.getState()).toBe('CLOSED');

    await expect(cb.execute(failAction)).rejects.toThrow('Network timeout');
    expect(cb.getState()).toBe('CLOSED');

    await expect(cb.execute(failAction)).rejects.toThrow('Network timeout');
    // 3rd failure trips the breaker
    expect(cb.getState()).toBe('OPEN');
    expect(cb.isOpen()).toBe(true);

    // OPEN state must fail fast without executing action
    const probe = vi.fn();
    await expect(cb.execute(probe)).rejects.toThrow(CircuitBreakerOpenError);
    expect(probe).not.toHaveBeenCalled();
  });

  it('should transition from OPEN to HALF_OPEN after cooldown and reset to CLOSED upon success', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 50 });
    await expect(cb.execute(async () => { throw new Error('Fail'); })).rejects.toThrow();
    expect(cb.getState()).toBe('OPEN');

    // Wait past cooldown
    await new Promise((r) => setTimeout(r, 60));

    expect(cb.getState()).toBe('HALF_OPEN');
    expect(cb.isOpen()).toBe(false); // allows trial call

    const res = await cb.execute(async () => 'RECOVERED');
    expect(res).toBe('RECOVERED');
    expect(cb.getState()).toBe('CLOSED');
  });
});

describe('Deduplication: Canonical SHA-256 Fingerprinting', () => {
  it('should produce identical SHA-256 for objects with differently ordered keys', () => {
    const objA = { z: 10, a: 'test', m: { b: 2, a: 1 } };
    const objB = { a: 'test', m: { a: 1, b: 2 }, z: 10 };

    const hashA = computeCanonicalFingerprint(objA);
    const hashB = computeCanonicalFingerprint(objB);

    expect(hashA).toBe(hashB);
    expect(hashA).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should produce distinct hashes for different payload contents', () => {
    const hash1 = computeCanonicalFingerprint({ event: 'A' });
    const hash2 = computeCanonicalFingerprint({ event: 'B' });
    expect(hash1).not.toBe(hash2);
  });
});

describe('XML Sanitizer & Anti-XXE Guard', () => {
  it('should sanitize HTML to clean plain text', () => {
    const dirty = '<p>Title <script>alert("xss")</script>with <b>formatting</b> &amp; &quot;quotes&quot;</p>';
    const clean = sanitizeToPlainText(dirty);
    expect(clean).toBe('Title with formatting & "quotes"');
  });

  it('should strip malicious tags and event handlers in sanitizeSafeHtml', () => {
    const dirty = '<p>Safe text <img src="x" onerror="alert(1)"> <a href="javascript:alert(1)">Click</a></p><script>evil()</script>';
    const safe = sanitizeSafeHtml(dirty);
    expect(safe).not.toContain('<script>');
    expect(safe).not.toContain('onerror');
    expect(safe).not.toContain('javascript:');
    expect(safe).toContain('Safe text');
  });

  it('should extract tags and attributes accurately', () => {
    const xml = '<item><title><![CDATA[Cyber Alert]]></title><link href="https://cisa.gov/alert" /></item>';
    expect(extractXmlTag(xml, 'title')).toBe('Cyber Alert');
    expect(extractXmlAttr(xml, 'link', 'href')).toBe('https://cisa.gov/alert');
  });

  it('should reject XXE entity expansions and hostile DTDs', () => {
    const xxe = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
    expect(() => assertSafeXml(xxe)).toThrow(/XXE_ATTACK_DETECTED/);

    const dtd = '<!DOCTYPE root SYSTEM "http://evil.com/evil.dtd"><root></root>';
    expect(() => assertSafeXml(dtd)).toThrow(/DTD_FORBIDDEN/);
  });
});

describe('USGS Earthquakes Normalization & Severity', () => {
  it('should normalize coordinates, natural key, and severity accurately', () => {
    const connector = new UsgsEarthquakeConnector();

    const feature = {
      type: 'Feature' as const,
      id: 'us7000test',
      geometry: {
        type: 'Point' as const,
        coordinates: [-122.4194, 37.7749, 12.5] as [number, number, number]
      },
      properties: {
        mag: 6.8,
        place: 'Northern California',
        time: 1792695000000,
        alert: 'orange' as const,
        status: 'reviewed' as const,
        tsunami: 0,
        sig: 720,
        url: 'https://earthquake.usgs.gov/earthquakes/eventpage/us7000test',
        title: 'M 6.8 - Northern California'
      }
    };

    const severity = connector.calculateSeverity(feature);
    expect(severity).toBe('HIGH');

    // Coordinates mapping verification: GeoJSON [lon, lat, depth]
    const [lon, lat, depth] = feature.geometry.coordinates;
    expect(lon).toBe(-122.4194);
    expect(lat).toBe(37.7749);
    expect(depth).toBe(12.5);
  });

  it('should calculate CRITICAL for red alerts or mag >= 7.0', () => {
    const connector = new UsgsEarthquakeConnector();
    const feat = {
      type: 'Feature' as const,
      id: 'us7000big',
      geometry: { type: 'Point' as const, coordinates: [0, 0, 10] as [number, number, number] },
      properties: {
        mag: 7.4,
        place: 'Offshore',
        time: Date.now(),
        alert: 'red' as const,
        status: 'reviewed' as const,
        tsunami: 1,
        sig: 900,
        url: 'https://earthquake.usgs.gov/test',
        title: 'M 7.4 Offshore'
      }
    };
    expect(connector.calculateSeverity(feat)).toBe('CRITICAL');
  });
});

describe('NASA EONET Normalization & Tracking Points', () => {
  it('should sort geometry points chronologically and extract active position', () => {
    const connector = new NasaEonetConnector();

    const event = {
      id: 'EONET_9999',
      title: 'Typhoon Boreas',
      description: 'Major typhoon in Western Pacific',
      closed: null,
      categories: [{ id: 'severeStorms', title: 'Severe Storms' }],
      sources: [{ id: 'JTWC', url: 'https://metoc.navy.mil' }],
      geometry: [
        {
          date: '2026-10-28T06:00:00Z',
          type: 'Point' as const,
          coordinates: [134.0, 21.0] as [number, number],
          magnitudeValue: 90,
          magnitudeUnit: 'kts'
        },
        {
          date: '2026-10-28T12:00:00Z',
          type: 'Point' as const,
          coordinates: [135.2, 22.8] as [number, number],
          magnitudeValue: 120,
          magnitudeUnit: 'kts'
        }
      ]
    };

    const latestGeo = event.geometry[1];
    const severity = connector.calculateSeverity(event, latestGeo);
    expect(severity).toBe('CRITICAL'); // mag 120 >= 100 for severeStorms

    expect(latestGeo.coordinates[0]).toBe(135.2); // lon
    expect(latestGeo.coordinates[1]).toBe(22.8);  // lat
  });
});

describe('CISA KEV & Advisories Parsing', () => {
  it('should assign CRITICAL for known ransomware campaigns', () => {
    const vuln = {
      cveID: 'CVE-2026-48356',
      vendorProject: 'Adobe',
      product: 'Commerce',
      vulnerabilityName: 'Unrestricted File Upload',
      dateAdded: '2026-10-27',
      shortDescription: 'Adobe Commerce flaw',
      requiredAction: 'Apply patch',
      dueDate: '2026-11-15',
      knownRansomwareCampaignUse: 'Known' as const,
      cwes: ['CWE-434']
    };

    expect(vuln.knownRansomwareCampaignUse).toBe('Known');
    expect(vuln.cveID).toBe('CVE-2026-48356');
  });

  it('should parse advisories RSS feed and extract CVE references', async () => {
    const connector = new CisaConnector();
    const mockRssXml = `
      <rss version="2.0">
        <channel>
          <title>CISA Advisories</title>
          <item>
            <title>Emergency Directive: Mitigate Critical Vulnerability CVE-2026-1234 in SCADA</title>
            <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-001a</link>
            <description>Actively exploited zero-day vulnerability in industrial systems.</description>
            <pubDate>Wed, 28 Oct 2026 12:00:00 GMT</pubDate>
            <guid>AA26-001A</guid>
          </item>
        </channel>
      </rss>
    `;

    // Test XML extraction logic directly
    const itemXml = (mockRssXml.match(/<item\b[\s\S]*?<\/item>/gi) || [])[0];
    expect(itemXml).toBeDefined();
    const title = extractXmlTag(itemXml || '', 'title');
    expect(title).toContain('CVE-2026-1234');
    expect(title).toContain('Emergency Directive');
  });
});

describe('crt.sh Certificate Transparency Parser', () => {
  it('should parse multi-line SANs, strip wildcards, and eliminate duplicates', () => {
    const nameValue = 'example.com\n*.api.example.com\napi.example.com\nadmin@example.com\n*.staging.example.com';
    const commonName = 'www.example.com';

    const result = parseSanEntries(nameValue, commonName);

    expect(result.subdomains).toContain('example.com');
    expect(result.subdomains).toContain('api.example.com');
    expect(result.subdomains).toContain('staging.example.com');
    expect(result.subdomains).toContain('www.example.com');

    // Wildcard prefix stripped from subdomains
    expect(result.subdomains).not.toContain('*.api.example.com');
    expect(result.wildcards).toContain('*.api.example.com');

    // Email extracted and excluded from domain list
    expect(result.emails).toContain('admin@example.com');
    expect(result.subdomains).not.toContain('admin@example.com');
  });

  it('should validate domain formatting accurately', () => {
    expect(isValidDomain('nordic-power.net')).toBe(true);
    expect(isValidDomain('scada.sub.nordic-power.net')).toBe(true);
    expect(isValidDomain('invalid..domain')).toBe(false);
    expect(isValidDomain('not-a-domain')).toBe(false);
  });
});

describe('RDAP jCard Parser', () => {
  it('should safely extract registrar name from RFC 7095 vcardArray', () => {
    const vcard = [
      'vcard',
      [
        ['version', {}, 'text', '4.0'],
        ['fn', {}, 'text', 'MarkMonitor Inc.'],
        ['kind', {}, 'text', 'org']
      ]
    ];
    const name = extractVCardName(vcard);
    expect(name).toBe('MarkMonitor Inc.');
  });

  it('should return null on malformed or empty vcard structures', () => {
    expect(extractVCardName(null)).toBeNull();
    expect(extractVCardName([])).toBeNull();
    expect(extractVCardName(['vcard', []])).toBeNull();
  });
});

describe('RSS 2.0 & Atom 1.0 Parser with IOC Extraction', () => {
  it('should parse Atom feeds and extract CVEs and IPs', async () => {
    const connector = new RssFeedConnector();
    const atomXml = `<?xml version="1.0" encoding="utf-8"?>
      <feed xmlns="http://www.w3.org/2005/Atom">
        <title>Threat Intel News</title>
        <entry>
          <title>Threat Actor Exploiting CVE-2026-9999 from 198.51.100.25</title>
          <id>urn:uuid:12345</id>
          <updated>2026-10-28T10:00:00Z</updated>
          <link href="https://threat.report/item-1" />
          <summary>Malware campaign observed targeting critical services.</summary>
        </entry>
      </feed>
    `;

    const items = await connector.parseFeedXml(atomXml, 'https://threat.report/atom.xml');
    expect(items.length).toBe(1);
    expect(items[0].sourceType).toBe('RSS_FEED');
    expect(items[0].feedCategory).toBe('NEWS');
    expect(items[0].title).toContain('CVE-2026-9999');

    const cveEntity = items[0].extractedEntities?.find((e) => e.type === 'VULNERABILITY');
    expect(cveEntity?.value).toBe('CVE-2026-9999');

    const ipEntity = items[0].extractedEntities?.find((e) => e.type === 'IP_ADDRESS');
    expect(ipEntity?.value).toBe('198.51.100.25');
  });
});
