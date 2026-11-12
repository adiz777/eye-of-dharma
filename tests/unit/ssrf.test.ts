// tests/unit/ssrf.test.ts
// Unit tests for 6-Stage Multi-Stage SSRF Firewall

import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { validateUrlForSsrf, isIpForbidden, safeFetch } from '../../server/security/ssrf.js';

describe('SSRF Firewall - Stage 1: Scheme and Syntax Validation', () => {
  it('should accept valid http and https URLs', async () => {
    const mockResolver = async () => [{ address: '93.184.216.34', family: 4 }];
    const resHttp = await validateUrlForSsrf('http://example.com/api', { dnsResolver: mockResolver });
    expect(resHttp.allowed).toBe(true);

    const resHttps = await validateUrlForSsrf('https://example.com/feed.xml', { dnsResolver: mockResolver });
    expect(resHttps.allowed).toBe(true);
  });

  it('should reject non-HTTP protocols', async () => {
    const disallowedProtocols = [
      'ftp://example.com/file.txt',
      'file:///etc/passwd',
      'gopher://127.0.0.1:70',
      'dict://127.0.0.1:2628',
      'data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==',
      'ldap://127.0.0.1:389'
    ];

    for (const url of disallowedProtocols) {
      const res = await validateUrlForSsrf(url);
      expect(res.allowed).toBe(false);
      expect(res.error).toBe('SSRF_DISALLOWED_PROTOCOL');
    }
  });

  it('should reject embedded user credentials in URLs', async () => {
    const res = await validateUrlForSsrf('http://admin:secret@example.com/data');
    expect(res.allowed).toBe(false);
    expect(res.error).toBe('SSRF_CREDENTIALS_DISALLOWED');
  });

  it('should reject malformed or empty URLs', async () => {
    expect((await validateUrlForSsrf('')).allowed).toBe(false);
    expect((await validateUrlForSsrf('not-a-valid-url')).allowed).toBe(false);
  });
});

describe('SSRF Firewall - Stage 4: CIDR Subnet Range Enforcement', () => {
  it('should block all RFC 1122 and RFC 1918 IPv4 private addresses', () => {
    const privateIps = [
      '127.0.0.1',
      '127.0.1.1',
      '127.255.255.254',
      '10.0.0.1',
      '10.254.1.42',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.0.1',
      '192.168.100.50',
      '0.0.0.0',
      '0.42.0.1'
    ];

    for (const ip of privateIps) {
      const result = isIpForbidden(ip);
      expect(result.forbidden).toBe(true);
      expect(result.matchedCidr).toBeDefined();
    }
  });

  it('should block Link-Local and Cloud Metadata IPv4 addresses (RFC 3927)', () => {
    const metadataIps = [
      '169.254.169.254', // AWS / Azure / GCP instance metadata
      '169.254.1.1',
      '169.254.254.254'
    ];

    for (const ip of metadataIps) {
      const result = isIpForbidden(ip);
      expect(result.forbidden).toBe(true);
      expect(result.matchedCidr).toBe('169.254.0.0/16');
    }
  });

  it('should block Shared Address Space, Test-Nets, and Multicast', () => {
    const restrictedIps = [
      '100.64.0.1', // CGNAT
      '192.0.2.1', // TEST-NET-1
      '198.51.100.1', // TEST-NET-2
      '203.0.113.1', // TEST-NET-3
      '224.0.0.1', // Multicast
      '240.0.0.1', // Reserved
      '255.255.255.255' // Broadcast
    ];

    for (const ip of restrictedIps) {
      const result = isIpForbidden(ip);
      expect(result.forbidden).toBe(true);
    }
  });

  it('should block IPv6 loopback, link-local, and ULA addresses', () => {
    const restrictedIpv6 = [
      '::1',
      '::',
      'fe80::1',
      'fc00::1',
      'fd00::1234',
      '::7f00:1',
      '64:ff9b:1::127.0.0.1'
    ];

    for (const ip of restrictedIpv6) {
      const result = isIpForbidden(ip);
      expect(result.forbidden).toBe(true);
    }
  });

  it('should detect and block IPv4-mapped IPv6 bypass vectors', () => {
    const mappedIps = [
      '::ffff:127.0.0.1',
      '::ffff:169.254.169.254',
      '::ffff:10.0.0.1',
      '::ffff:192.168.1.1'
    ];

    for (const ip of mappedIps) {
      const result = isIpForbidden(ip);
      expect(result.forbidden).toBe(true);
      expect(result.reason).toContain('IPv4-mapped');
    }
  });

  it('should allow legitimate public IPv4 and IPv6 addresses', () => {
    const publicIps = [
      '8.8.8.8',
      '1.1.1.1',
      '93.184.216.34',
      '2606:4700:4700::1111'
    ];

    for (const ip of publicIps) {
      const result = isIpForbidden(ip);
      expect(result.forbidden).toBe(false);
    }
  });
});

describe('SSRF Firewall - Stage 2 & 3: Obfuscation and DNS Resolution', () => {
  it('should block numeric and hex obfuscated loopbacks', async () => {
    // 0x7f000001, 017700000001, 2130706433 all represent 127.0.0.1
    const obfuscated = [
      'http://127.0.0.1/admin',
      'http://0x7f000001/admin',
      'http://2130706433/admin'
    ];

    for (const url of obfuscated) {
      const res = await validateUrlForSsrf(url);
      expect(res.allowed).toBe(false);
      expect(res.error).toBe('SSRF_BLOCKED');
    }
  });

  it('should handle DNS resolution failure', async () => {
    const failingResolver = async () => {
      throw new Error('getaddrinfo ENOTFOUND invalid-non-existent-domain.xyz');
    };

    const res = await validateUrlForSsrf('https://invalid-non-existent-domain.xyz/test', {
      dnsResolver: failingResolver
    });

    expect(res.allowed).toBe(false);
    expect(res.error).toBe('DNS_RESOLUTION_FAILED');
  });

  it('should block hostname when DNS resolves to a private IP', async () => {
    const privateResolver = async () => [{ address: '10.0.0.5', family: 4 }];

    const res = await validateUrlForSsrf('https://internal.mycorp.local', {
      dnsResolver: privateResolver
    });

    expect(res.allowed).toBe(false);
    expect(res.error).toBe('SSRF_BLOCKED');
  });

  it('should block hostname if ANY resolved IP is private', async () => {
    const dualResolver = async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 }
    ];

    const res = await validateUrlForSsrf('https://rebind-test.attacker.com', {
      dnsResolver: dualResolver
    });

    expect(res.allowed).toBe(false);
    expect(res.error).toBe('SSRF_BLOCKED');
  });
});

describe('SSRF Firewall - Stage 5 & 6: Safe HTTP Client Protection', () => {
  it('should enforce response size cap (abort when > maxBytes)', async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      // Send 200KB of 'A's
      const chunk = Buffer.alloc(50 * 1024, 'A');
      for (let i = 0; i < 4; i++) {
        res.write(chunk);
      }
      res.end();
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as import('net').AddressInfo).port;

    try {
      await expect(
        safeFetch(`http://127.0.0.1:${port}/large`, {
          maxBytes: 10 * 1024, // 10KB cap
          allowPrivateForTesting: true
        })
      ).rejects.toThrow('PAYLOAD_TOO_LARGE');
    } finally {
      server.close();
    }
  });

  it('should enforce request timeout (abort when > timeoutMs)', async () => {
    const server = http.createServer((_req, _res) => {
      // Never respond
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as import('net').AddressInfo).port;

    try {
      await expect(
        safeFetch(`http://127.0.0.1:${port}/slow`, {
          timeoutMs: 100, // 100ms timeout
          allowPrivateForTesting: true
        })
      ).rejects.toThrow('REQUEST_TIMEOUT');
    } finally {
      server.close();
    }
  });

  it('should validate redirects and block redirecting to a private IP', async () => {
    let serverHit = false;
    const server = http.createServer((_req, res) => {
      serverHit = true;
      res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as import('net').AddressInfo).port;

    try {
      await expect(
        safeFetch(`http://127.0.0.1:${port}/redirect`, {
          allowPrivateForTesting: true,
          allowPrivateRedirects: false
        })
      ).rejects.toThrow('SSRF_BLOCKED');
      expect(serverHit).toBe(true);
    } finally {
      server.close();
    }
  });
});
