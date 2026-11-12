// tests/unit/ssrf_adversarial.test.ts
// Adversarial Stress Test Suite for 6-Stage SSRF Firewall
// Executed by SSRF Adversarial Challenger (Milestone M1)

import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import {
  validateUrlForSsrf,
  isIpForbidden,
  safeFetch,
  DnsResolverFn
} from '../../server/security/ssrf.js';

describe('Adversarial SSRF Suite 1: Obfuscated Decimal / Hex / Octal IPv4 Encodings', () => {
  const loopbackVariants = [
    { name: 'Standard loopback', url: 'http://127.0.0.1/api' },
    { name: 'Secondary loopback IP', url: 'http://127.0.1.1/' },
    { name: 'High-range loopback IP', url: 'http://127.127.127.127/' },
    { name: 'Boundary loopback IP', url: 'http://127.255.255.254/' },
    { name: 'Dword decimal loopback', url: 'http://2130706433/' },
    { name: 'Full hex loopback', url: 'http://0x7f000001/' },
    { name: 'Hex first octet', url: 'http://0x7f.0.0.1/' },
    { name: 'Hex + dword shorthand', url: 'http://0x7f.1/' },
    { name: 'All hex octets', url: 'http://0x7f.0x0.0x0.0x1/' },
    { name: 'Octal 12-digit loopback', url: 'http://017700000001/' },
    { name: 'Octal first octet', url: 'http://0177.0.0.1/' },
    { name: 'Octal all octets', url: 'http://0177.0000.0000.0001/' },
    { name: 'Octal leading zero mix', url: 'http://0177.0.0.01/' },
    { name: 'Two-octet class A shorthand', url: 'http://127.1/' },
    { name: 'Three-octet shorthand', url: 'http://127.0.1/' },
    { name: 'Single zero IP', url: 'http://0/' },
    { name: 'Dotted quad zero IP', url: 'http://0.0.0.0/' }
  ];

  for (const { name, url } of loopbackVariants) {
    it(`should block ${name} (${url})`, async () => {
      const result = await validateUrlForSsrf(url);
      expect(result.allowed).toBe(false);
      expect(['SSRF_BLOCKED', 'SSRF_MALFORMED_URL', 'INVALID_IP_FORMAT']).toContain(result.error);
    });
  }

  const metadataVariants = [
    { name: 'Standard AWS/Azure/GCP metadata', url: 'http://169.254.169.254/latest/meta-data/' },
    { name: 'Dword decimal metadata', url: 'http://2852039166/latest/meta-data/' },
    { name: 'Full hex metadata', url: 'http://0xa9fea9fe/latest/meta-data/' },
    { name: 'All hex octets metadata', url: 'http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/' },
    { name: 'Octal all octets metadata', url: 'http://0251.0376.0251.0376/latest/meta-data/' },
    { name: 'Octal 12-digit metadata', url: 'http://025177524776/latest/meta-data/' },
    { name: 'Link-local lower boundary', url: 'http://169.254.0.1/' },
    { name: 'Link-local upper boundary', url: 'http://169.254.255.254/' }
  ];

  for (const { name, url } of metadataVariants) {
    it(`should block cloud metadata variant ${name} (${url})`, async () => {
      const result = await validateUrlForSsrf(url);
      expect(result.allowed).toBe(false);
      expect(['SSRF_BLOCKED', 'SSRF_MALFORMED_URL', 'INVALID_IP_FORMAT']).toContain(result.error);
    });
  }

  const rfc1918Variants = [
    { name: '10.0.0.1 standard', url: 'http://10.0.0.1/' },
    { name: '10.0.0.1 hex dword', url: 'http://0x0a000001/' },
    { name: '10.0.0.1 decimal dword', url: 'http://167772161/' },
    { name: '10.255.255.254 boundary', url: 'http://10.255.255.254/' },
    { name: '172.16.0.1 standard', url: 'http://172.16.0.1/' },
    { name: '172.16.0.1 hex dword', url: 'http://0xac100001/' },
    { name: '172.31.255.254 boundary', url: 'http://172.31.255.254/' },
    { name: '192.168.1.1 standard', url: 'http://192.168.1.1/' },
    { name: '192.168.1.1 hex dword', url: 'http://0xc0a80101/' },
    { name: '192.168.1.1 decimal dword', url: 'http://3232235777/' },
    { name: '192.168.255.254 boundary', url: 'http://192.168.255.254/' }
  ];

  for (const { name, url } of rfc1918Variants) {
    it(`should block RFC 1918 variant ${name} (${url})`, async () => {
      const result = await validateUrlForSsrf(url);
      expect(result.allowed).toBe(false);
      expect(['SSRF_BLOCKED', 'SSRF_MALFORMED_URL']).toContain(result.error);
    });
  }
});

describe('Adversarial SSRF Suite 2: IPv6 and IPv4-Mapped / IPv4-Compatible Vectors', () => {
  const robustIpv6Vectors = [
    { name: 'IPv6 standard loopback', url: 'http://[::1]/' },
    { name: 'IPv6 fully-expanded loopback', url: 'http://[0:0:0:0:0:0:0:1]/' },
    { name: 'IPv6 32-digit zero-padded loopback', url: 'http://[0000:0000:0000:0000:0000:0000:0000:0001]/' },
    { name: 'IPv6 unspecified address', url: 'http://[::]/' },
    { name: 'IPv4-mapped IPv6 loopback (dotted quad)', url: 'http://[::ffff:127.0.0.1]/' },
    { name: 'IPv4-mapped IPv6 loopback (hex format)', url: 'http://[::ffff:7f00:1]/' },
    { name: 'IPv4-mapped IPv6 loopback (hex zero-padded)', url: 'http://[::ffff:7f00:0001]/' },
    { name: 'IPv4-mapped IPv6 cloud metadata (dotted quad)', url: 'http://[::ffff:169.254.169.254]/' },
    { name: 'IPv4-mapped IPv6 cloud metadata (hex format)', url: 'http://[::ffff:a9fe:a9fe]/' },
    { name: 'IPv4-mapped IPv6 10.0.0.1', url: 'http://[::ffff:10.0.0.1]/' },
    { name: 'IPv4-mapped IPv6 10.0.0.1 (hex format)', url: 'http://[::ffff:0a00:0001]/' },
    { name: 'IPv4-mapped IPv6 192.168.1.1', url: 'http://[::ffff:192.168.1.1]/' },
    { name: 'IPv4-mapped IPv6 192.168.1.1 (hex format)', url: 'http://[::ffff:c0a8:0101]/' },
    { name: 'IPv4-mapped IPv6 fully expanded', url: 'http://[0:0:0:0:0:ffff:127.0.0.1]/' },
    { name: 'IPv6 link-local unicast fe80::', url: 'http://[fe80::1]/' },
    { name: 'IPv6 Unique Local Address fc00::', url: 'http://[fc00::1]/' },
    { name: 'IPv6 Unique Local Address fd00::', url: 'http://[fd00::1]/' },
    { name: 'AWS IPv6 metadata endpoint fd00:ec2::254', url: 'http://[fd00:ec2::254]/' },
    { name: 'RFC 6052 local IPv4 translation', url: 'http://[64:ff9b::127.0.0.1]/' },
    { name: 'RFC 6666 discard prefix 100::', url: 'http://[100::1]/' },
    { name: 'RFC 3849 documentation prefix 2001:db8::', url: 'http://[2001:db8::1]/' },
    { name: 'RFC 3056 6to4 prefix 2002::', url: 'http://[2002:7f00:0001::]/' }
  ];

  for (const { name, url } of robustIpv6Vectors) {
    it(`should block ${name} (${url})`, async () => {
      const result = await validateUrlForSsrf(url);
      expect(result.allowed).toBe(false);
      expect(['SSRF_BLOCKED', 'SSRF_MALFORMED_URL']).toContain(result.error);
    });
  }

  it('should verify isIpForbidden detects bracketed and unbracketed IPv6 addresses', () => {
    expect(isIpForbidden('[::1]').forbidden).toBe(true);
    expect(isIpForbidden('::1').forbidden).toBe(true);
    expect(isIpForbidden('[::ffff:127.0.0.1]').forbidden).toBe(true);
    expect(isIpForbidden('::ffff:127.0.0.1').forbidden).toBe(true);
    expect(isIpForbidden('[fd00:ec2::254]').forbidden).toBe(true);
    expect(isIpForbidden('fd00:ec2::254').forbidden).toBe(true);
  });

  // --- ADVERSARIAL CHALLENGER VULNERABILITY AUDIT TESTS ---
  // The following tests document the exact bypasses uncovered in server/security/ssrf.ts:
  it('should block IPv4-compatible IPv6 loopback (::127.0.0.1 / ::7f00:1)', async () => {
    const resultDotted = await validateUrlForSsrf('http://[::127.0.0.1]/');
    const resultHex = await validateUrlForSsrf('http://[::7f00:1]/');
    
    expect(resultDotted.allowed).toBe(false);
    expect(resultDotted.error).toBe('SSRF_BLOCKED');
    expect(resultHex.allowed).toBe(false);
    expect(resultHex.error).toBe('SSRF_BLOCKED');
  });

  it('should block IPv4-compatible IPv6 Cloud Metadata (::169.254.169.254 / ::a9fe:a9fe)', async () => {
    const resultDotted = await validateUrlForSsrf('http://[::169.254.169.254]/');
    const resultHex = await validateUrlForSsrf('http://[::a9fe:a9fe]/');
    
    expect(resultDotted.allowed).toBe(false);
    expect(resultDotted.error).toBe('SSRF_BLOCKED');
    expect(resultHex.allowed).toBe(false);
    expect(resultHex.error).toBe('SSRF_BLOCKED');
  });

  it('should block RFC 8215 local IPv4/IPv6 translation prefix (64:ff9b:1::/48)', async () => {
    const check = isIpForbidden('64:ff9b:1::127.0.0.1');
    expect(check.forbidden).toBe(true);
    expect(check.matchedCidr).toBe('64:ff9b:1::/48');
  });
});

describe('Adversarial SSRF Suite 3: Non-HTTP Schemes & Credentials Injection', () => {
  const dangerousProtocols = [
    'file:///etc/passwd',
    'file:///c:/windows/win.ini',
    'file://localhost/etc/shadow',
    'gopher://127.0.0.1:70/_GET%20/HTTP/1.0',
    'ftp://anonymous:guest@127.0.0.1/',
    'sftp://127.0.0.1:22/',
    'dict://127.0.0.1:2628/d:foo',
    'ldap://127.0.0.1:389/o=example',
    'tftp://127.0.0.1:69/file',
    'ws://127.0.0.1:8080/stream',
    'wss://127.0.0.1:8443/stream',
    'javascript:alert(document.cookie)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'blob:https://example.com/550e8400-e29b-41d4-a716-446655440000',
    'mailto:root@localhost',
    'ssh://root@127.0.0.1'
  ];

  for (const url of dangerousProtocols) {
    it(`should reject forbidden protocol: ${url}`, async () => {
      const result = await validateUrlForSsrf(url);
      expect(result.allowed).toBe(false);
      expect(result.error).toBe('SSRF_DISALLOWED_PROTOCOL');
    });
  }

  const credentialsUrls = [
    'http://admin:secret@example.com/dashboard',
    'http://user:password@127.0.0.1/admin',
    'http://user@example.com/',
    'http://:secret@example.com/',
    'https://token:x-oauth-basic@github.com/repo',
    'http://foo:bar@169.254.169.254/latest/meta-data/'
  ];

  for (const url of credentialsUrls) {
    it(`should reject embedded credentials: ${url}`, async () => {
      const result = await validateUrlForSsrf(url);
      expect(result.allowed).toBe(false);
      expect(result.error).toBe('SSRF_CREDENTIALS_DISALLOWED');
    });
  }
});

describe('Adversarial SSRF Suite 4: DNS Rebinding and Multi-IP Resolution', () => {
  it('should block multi-homed hostname when private IP is in 2nd position', async () => {
    const multiResolver: DnsResolverFn = async () => [
      { address: '93.184.216.34', family: 4 }, // public
      { address: '127.0.0.1', family: 4 }      // private
    ];

    const result = await validateUrlForSsrf('https://dual-homed-attack.com/api', {
      dnsResolver: multiResolver
    });

    expect(result.allowed).toBe(false);
    expect(result.error).toBe('SSRF_BLOCKED');
    expect(result.reason).toContain('127.0.0.1 is forbidden');
  });

  it('should block multi-homed hostname when private IP is in 1st position', async () => {
    const multiResolver: DnsResolverFn = async () => [
      { address: '10.0.0.1', family: 4 },      // private
      { address: '93.184.216.34', family: 4 }  // public
    ];

    const result = await validateUrlForSsrf('https://dual-homed-attack.com/api', {
      dnsResolver: multiResolver
    });

    expect(result.allowed).toBe(false);
    expect(result.error).toBe('SSRF_BLOCKED');
  });

  it('should block multi-homed hostname when public IPv4 is paired with private IPv6 (::1)', async () => {
    const dualStackResolver: DnsResolverFn = async () => [
      { address: '93.184.216.34', family: 4 }, // public IPv4
      { address: '::1', family: 6 }            // private IPv6 loopback
    ];

    const result = await validateUrlForSsrf('https://dual-stack-rebind.com/api', {
      dnsResolver: dualStackResolver
    });

    expect(result.allowed).toBe(false);
    expect(result.error).toBe('SSRF_BLOCKED');
    expect(result.reason).toContain('::1 is forbidden');
  });

  it('should block multi-homed hostname when public IPv4 is paired with AWS IPv6 metadata (fd00:ec2::254)', async () => {
    const awsMetadataResolver: DnsResolverFn = async () => [
      { address: '93.184.216.34', family: 4 },
      { address: 'fd00:ec2::254', family: 6 }
    ];

    const result = await validateUrlForSsrf('https://aws-meta-rebind.com/api', {
      dnsResolver: awsMetadataResolver
    });

    expect(result.allowed).toBe(false);
    expect(result.error).toBe('SSRF_BLOCKED');
  });

  it('should reject when DNS resolver returns an empty records array', async () => {
    const emptyResolver: DnsResolverFn = async () => [];
    const result = await validateUrlForSsrf('https://empty-dns.example.com', {
      dnsResolver: emptyResolver
    });
    expect(result.allowed).toBe(false);
    expect(result.error).toBe('DNS_RESOLUTION_FAILED');
  });

  it('should reject when DNS resolver throws an unexpected network error', async () => {
    const throwingResolver: DnsResolverFn = async () => {
      throw new Error('SERVFAIL: DNS server unavailable');
    };
    const result = await validateUrlForSsrf('https://servfail.example.com', {
      dnsResolver: throwingResolver
    });
    expect(result.allowed).toBe(false);
    expect(result.error).toBe('DNS_RESOLUTION_FAILED');
    expect(result.reason).toContain('SERVFAIL');
  });
});

describe('Adversarial SSRF Suite 5: URL Syntax and Normalization Quirks', () => {
  it('should reject URLs with illegal null bytes or spaces in hostname', async () => {
    const invalidUrls = [
      'http://example\0.com',
      'http://example com',
      'http://127.0.0.1%00/',
      'http://127.0.0.1%20/'
    ];

    for (const url of invalidUrls) {
      const res = await validateUrlForSsrf(url);
      expect(res.allowed).toBe(false);
      expect(['SSRF_MALFORMED_URL', 'SSRF_BLOCKED']).toContain(res.error);
    }
  });

  it('should strip carriage returns and tabs per WHATWG URL standard while blocking private IPs', async () => {
    // WHATWG URL strips \r, \n, \t during parsing
    const privateWithCr = await validateUrlForSsrf('http://127.0\r.0.1/');
    expect(privateWithCr.allowed).toBe(false);
    expect(privateWithCr.error).toBe('SSRF_BLOCKED');

    const metadataWithTab = await validateUrlForSsrf('http://169.254\t.169.254/');
    expect(metadataWithTab.allowed).toBe(false);
    expect(metadataWithTab.error).toBe('SSRF_BLOCKED');
  });

  it('should normalize mixed case schemes and uppercase hostnames', async () => {
    const mockResolver: DnsResolverFn = async () => [{ address: '93.184.216.34', family: 4 }];
    const resUpper = await validateUrlForSsrf('HTTP://EXAMPLE.COM/test', { dnsResolver: mockResolver });
    expect(resUpper.allowed).toBe(true);
    expect(resUpper.normalizedUrl).toBe('http://example.com/test');

    const resMixed = await validateUrlForSsrf('hTtPs://ExAmPlE.cOm/path', { dnsResolver: mockResolver });
    expect(resMixed.allowed).toBe(true);
    expect(resMixed.normalizedUrl).toBe('https://example.com/path');
  });

  it('should trim surrounding whitespace', async () => {
    const mockResolver: DnsResolverFn = async () => [{ address: '93.184.216.34', family: 4 }];
    const res = await validateUrlForSsrf('   https://example.com/feed   ', { dnsResolver: mockResolver });
    expect(res.allowed).toBe(true);
    expect(res.normalizedUrl).toBe('https://example.com/feed');
  });

  it('should properly block trailing dot localhost and 127.0.0.1', async () => {
    const resLocalhost = await validateUrlForSsrf('http://localhost./');
    expect(resLocalhost.allowed).toBe(false);

    const resDotIp = await validateUrlForSsrf('http://127.0.0.1./');
    expect(resDotIp.allowed).toBe(false);
  });
});

describe('Adversarial SSRF Suite 6: safeFetch IP Pinning, Redirect Hijacks, Size Limits & Timeouts', () => {
  it('should verify IP Pinning transmits the target Host header to the pinned IP socket', async () => {
    let capturedHostHeader = '';
    const testServer = http.createServer((req, res) => {
      capturedHostHeader = req.headers.host || '';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', pinned: true }));
    });

    await new Promise<void>((resolve) => testServer.listen(0, '127.0.0.1', resolve));
    const port = (testServer.address() as AddressInfo).port;

    try {
      const mockResolver: DnsResolverFn = async () => [
        { address: '127.0.0.1', family: 4 }
      ];

      const res = await safeFetch(`http://spoofed-victim.com:${port}/test`, {
        dnsResolver: mockResolver,
        allowPrivateForTesting: true // Allows 127.0.0.1 for local test socket
      });

      expect(res.statusCode).toBe(200);
      expect(res.pinnedIp).toBe('127.0.0.1');
      // Verify Host header was preserved as the original domain (spoofed-victim.com)
      expect(capturedHostHeader).toBe(`spoofed-victim.com:${port}`);
    } finally {
      testServer.close();
    }
  });

  it('should block redirect attempting to pivot to private IP (127.0.0.1)', async () => {
    let serverHit = false;
    const testServer = http.createServer((_req, res) => {
      serverHit = true;
      res.writeHead(302, { Location: 'http://127.0.0.1:9999/internal-admin' });
      res.end();
    });

    await new Promise<void>((resolve) => testServer.listen(0, '127.0.0.1', resolve));
    const port = (testServer.address() as AddressInfo).port;

    try {
      const adaptiveResolver: DnsResolverFn = async () => [
        { address: '127.0.0.1', family: 4 }
      ];

      await expect(
        safeFetch(`http://public-service.org:${port}/entry`, {
          dnsResolver: adaptiveResolver,
          allowPrivateForTesting: true,
          allowPrivateRedirects: false
        })
      ).rejects.toThrow('SSRF_BLOCKED');
      expect(serverHit).toBe(true);
    } finally {
      testServer.close();
    }
  });

  it('should block redirect attempting to pivot to Cloud Metadata (169.254.169.254)', async () => {
    let serverHit = false;
    const testServer = http.createServer((_req, res) => {
      serverHit = true;
      res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    });

    await new Promise<void>((resolve) => testServer.listen(0, '127.0.0.1', resolve));
    const port = (testServer.address() as AddressInfo).port;

    try {
      await expect(
        safeFetch(`http://127.0.0.1:${port}/entry`, {
          allowPrivateForTesting: true,
          allowPrivateRedirects: false
        })
      ).rejects.toThrow('SSRF_BLOCKED');
      expect(serverHit).toBe(true);
    } finally {
      testServer.close();
    }
  });

  it('should detect and terminate circular redirect loops (A -> B -> A)', async () => {
    let port = 0;
    const testServer = http.createServer((req, res) => {
      if (req.url === '/loop-a') {
        res.writeHead(302, { Location: `http://127.0.0.1:${port}/loop-b` });
        res.end();
      } else if (req.url === '/loop-b') {
        res.writeHead(302, { Location: `http://127.0.0.1:${port}/loop-a` });
        res.end();
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => testServer.listen(0, '127.0.0.1', resolve));
    port = (testServer.address() as AddressInfo).port;

    try {
      await expect(
        safeFetch(`http://127.0.0.1:${port}/loop-a`, {
          allowPrivateForTesting: true,
          maxRedirects: 3
        })
      ).rejects.toThrow('MAX_REDIRECTS_EXCEEDED');
    } finally {
      testServer.close();
    }
  });

  it('should strictly enforce hard payload size limit (exact limit succeeds, limit + 1 aborts)', async () => {
    const exactLimit = 100 * 1024; // 100 KB
    let mode: 'exact' | 'exceeded' = 'exact';

    const testServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      if (mode === 'exact') {
        res.end(Buffer.alloc(exactLimit, 'X'));
      } else {
        // Exceed by 1 byte
        res.write(Buffer.alloc(exactLimit, 'X'));
        res.end(Buffer.from('Z'));
      }
    });

    await new Promise<void>((resolve) => testServer.listen(0, '127.0.0.1', resolve));
    const port = (testServer.address() as AddressInfo).port;

    try {
      // 1. Exact limit should PASS
      mode = 'exact';
      const exactRes = await safeFetch(`http://127.0.0.1:${port}/data`, {
        maxBytes: exactLimit,
        allowPrivateForTesting: true
      });
      expect(exactRes.data.length).toBe(exactLimit);

      // 2. Limit + 1 byte should FAIL with PAYLOAD_TOO_LARGE
      mode = 'exceeded';
      await expect(
        safeFetch(`http://127.0.0.1:${port}/data`, {
          maxBytes: exactLimit,
          allowPrivateForTesting: true
        })
      ).rejects.toThrow('PAYLOAD_TOO_LARGE');
    } finally {
      testServer.close();
    }
  });

  it('should abort connection when remote server hangs longer than timeoutMs', async () => {
    const testServer = http.createServer((_req, _res) => {
      // Intentionally do not send any headers or response body
    });

    await new Promise<void>((resolve) => testServer.listen(0, '127.0.0.1', resolve));
    const port = (testServer.address() as AddressInfo).port;

    try {
      const startTime = Date.now();
      await expect(
        safeFetch(`http://127.0.0.1:${port}/hang`, {
          timeoutMs: 150,
          allowPrivateForTesting: true
        })
      ).rejects.toThrow('REQUEST_TIMEOUT');
      const elapsed = Date.now() - startTime;
      expect(elapsed).toBeGreaterThanOrEqual(140);
      expect(elapsed).toBeLessThan(1000);
    } finally {
      testServer.close();
    }
  });
});
