// server/security/ssrf.ts
// 6-Stage Multi-Stage SSRF Firewall with IP Pinning & Safe HTTP Client

import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import ipaddr from 'ipaddr.js';

export interface SsrfCheckResult {
  allowed: boolean;
  error?: string;
  reason?: string;
  resolvedIps?: string[];
  pinnedIp?: string;
  matchedCidr?: string;
  normalizedUrl?: string;
}

export interface DnsResolverFn {
  (hostname: string): Promise<Array<{ address: string; family: number }>>;
}

export interface SsrfValidationOptions {
  dnsResolver?: DnsResolverFn;
  allowPrivateForTesting?: boolean;
}

// Forbidden IPv4 CIDR blocks
export const FORBIDDEN_IPV4_CIDRS: Array<[string, string]> = [
  ['0.0.0.0/8', 'This Network (RFC 1122)'],
  ['10.0.0.0/8', 'Private-Use (RFC 1918)'],
  ['100.64.0.0/10', 'Shared Address Space / CGNAT (RFC 6598)'],
  ['127.0.0.0/8', 'Loopback (RFC 1122)'],
  ['169.254.0.0/16', 'Link-Local / Cloud Metadata (RFC 3927)'],
  ['172.16.0.0/12', 'Private-Use (RFC 1918)'],
  ['192.0.0.0/24', 'IETF Protocol Assignments (RFC 6890)'],
  ['192.0.2.0/24', 'TEST-NET-1 (RFC 5737)'],
  ['192.88.99.0/24', '6to4 Relay Anycast (RFC 7526)'],
  ['192.168.0.0/16', 'Private-Use (RFC 1918)'],
  ['198.18.0.0/15', 'Network Benchmark Tests (RFC 2544)'],
  ['198.51.100.0/24', 'TEST-NET-2 (RFC 5737)'],
  ['203.0.113.0/24', 'TEST-NET-3 (RFC 5737)'],
  ['224.0.0.0/4', 'Multicast (RFC 5771)'],
  ['240.0.0.0/4', 'Reserved / Class E (RFC 1112)'],
  ['255.255.255.255/32', 'Limited Broadcast (RFC 919)']
];

// Forbidden IPv6 CIDR blocks
export const FORBIDDEN_IPV6_CIDRS: Array<[string, string]> = [
  ['::/128', 'Unspecified Address (RFC 4291)'],
  ['::1/128', 'Loopback (RFC 4291)'],
  ['::/96', 'IPv4-Compatible IPv6 (RFC 4291)'],
  ['::ffff:0:0/96', 'IPv4-mapped IPv6 (RFC 4291)'],
  ['::ffff:0:0:0/96', 'IPv4-translated (RFC 2765)'],
  ['64:ff9b::/96', 'Local IPv4/IPv6 translation (RFC 6052)'],
  ['64:ff9b:1::/48', 'Local-Use IPv4/IPv6 Translation (RFC 8215)'],
  ['100::/64', 'Discard Prefix (RFC 6666)'],
  ['2001:db8::/32', 'Documentation (RFC 3849)'],
  ['2002::/16', '6to4 Addressing (RFC 3056)'],
  ['fc00::/7', 'Unique Local Address - ULA (RFC 4193)'],
  ['fe80::/10', 'Link-Local Unicast (RFC 4291)'],
  ['fec0::/10', 'Site-Local (RFC 3879)'],
  ['ff00::/8', 'Multicast (RFC 4291)']
];

const PARSED_IPV4_CIDRS = FORBIDDEN_IPV4_CIDRS.map(([cidr, desc]) => ({
  cidr,
  range: ipaddr.parseCIDR(cidr),
  desc
}));

const PARSED_IPV6_CIDRS = FORBIDDEN_IPV6_CIDRS.map(([cidr, desc]) => ({
  cidr,
  range: ipaddr.parseCIDR(cidr),
  desc
}));

/**
 * Checks whether an IP address (IPv4 or IPv6) falls into any forbidden subnet.
 * Handles IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) by checking the embedded IPv4.
 */
export function isIpForbidden(ipStr: string): { forbidden: boolean; reason?: string; matchedCidr?: string } {
  try {
    // Strip IPv6 brackets if present
    const cleanIp = ipStr.replace(/^\[|\]$/g, '').trim();
    if (!ipaddr.isValid(cleanIp)) {
      return { forbidden: true, reason: 'INVALID_IP_FORMAT' };
    }

    const addr = ipaddr.parse(cleanIp);

    if (addr.kind() === 'ipv4') {
      const ipv4 = addr as ipaddr.IPv4;
      for (const item of PARSED_IPV4_CIDRS) {
        if (ipv4.match(item.range)) {
          return { forbidden: true, reason: item.desc, matchedCidr: item.cidr };
        }
      }
      return { forbidden: false };
    } else {
      const ipv6 = addr as ipaddr.IPv6;

      // Handle IPv4-mapped IPv6 addresses: extract IPv4 and inspect
      if (ipv6.isIPv4MappedAddress()) {
        const v4 = ipv6.toIPv4Address();
        for (const item of PARSED_IPV4_CIDRS) {
          if (v4.match(item.range)) {
            return {
              forbidden: true,
              reason: `IPv4-mapped ${item.desc}`,
              matchedCidr: `::ffff:${item.cidr}`
            };
          }
        }
      }

      for (const item of PARSED_IPV6_CIDRS) {
        if (ipv6.match(item.range)) {
          return { forbidden: true, reason: item.desc, matchedCidr: item.cidr };
        }
      }

      return { forbidden: false };
    }
  } catch {
    return { forbidden: true, reason: 'IP_PARSE_EXCEPTION' };
  }
}

/**
 * Default asynchronous DNS resolver
 */
export async function defaultDnsResolver(hostname: string): Promise<Array<{ address: string; family: number }>> {
  // If hostname is already an IP address
  const cleanHost = hostname.replace(/^\[|\]$/g, '').trim();
  if (ipaddr.isValid(cleanHost)) {
    const parsed = ipaddr.parse(cleanHost);
    return [{ address: cleanHost, family: parsed.kind() === 'ipv4' ? 4 : 6 }];
  }

  const records = await dns.promises.lookup(hostname, { all: true });
  return records;
}

/**
 * Multi-Stage SSRF Validator
 * Executes Stages 1 through 4 of the SSRF defense model.
 */
export async function validateUrlForSsrf(
  urlString: string,
  options: SsrfValidationOptions = {}
): Promise<SsrfCheckResult> {
  // Stage 1: Scheme and Syntax Validation
  if (!urlString || typeof urlString !== 'string') {
    return { allowed: false, error: 'SSRF_INVALID_INPUT', reason: 'URL must be a non-empty string' };
  }

  if (/^https?:\/\/\//i.test(urlString.trim())) {
    return { allowed: false, error: 'SSRF_MALFORMED_URL', reason: 'Malformed URL: empty authority' };
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlString.trim());
  } catch {
    return { allowed: false, error: 'SSRF_MALFORMED_URL', reason: 'Malformed URL could not be parsed' };
  }

  const protocol = parsedUrl.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    return {
      allowed: false,
      error: 'SSRF_DISALLOWED_PROTOCOL',
      reason: `Protocol '${parsedUrl.protocol}' is forbidden. Only http: and https: are allowed.`
    };
  }

  if (parsedUrl.username || parsedUrl.password) {
    return {
      allowed: false,
      error: 'SSRF_CREDENTIALS_DISALLOWED',
      reason: 'Embedded userinfo/credentials in URLs are prohibited.'
    };
  }

  // Stage 2: Hostname Character & Obfuscation Sanitization
  const rawHostname = parsedUrl.hostname;
  if (!rawHostname || rawHostname.length === 0) {
    return { allowed: false, error: 'SSRF_EMPTY_HOSTNAME', reason: 'Hostname is missing or empty' };
  }

  // Reject control characters or whitespace in hostname
  if (/[\s\x00-\x1F\x7F]/.test(rawHostname)) {
    return { allowed: false, error: 'SSRF_ILLEGAL_CHARACTERS', reason: 'Hostname contains illegal control characters' };
  }

  // Stage 3: Asynchronous DNS Resolution
  const resolver = options.dnsResolver || defaultDnsResolver;
  let resolvedRecords: Array<{ address: string; family: number }> = [];

  try {
    resolvedRecords = await resolver(rawHostname);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      allowed: false,
      error: 'DNS_RESOLUTION_FAILED',
      reason: `DNS resolution failed for hostname '${rawHostname}': ${message}`
    };
  }

  if (!resolvedRecords || resolvedRecords.length === 0) {
    return {
      allowed: false,
      error: 'DNS_RESOLUTION_FAILED',
      reason: `No DNS records resolved for hostname '${rawHostname}'`
    };
  }

  // Stage 4: CIDR Subnet Range Enforcement
  const resolvedIps = resolvedRecords.map((r) => r.address);

  if (!options.allowPrivateForTesting) {
    for (const record of resolvedRecords) {
      const check = isIpForbidden(record.address);
      if (check.forbidden) {
        return {
          allowed: false,
          error: 'SSRF_BLOCKED',
          reason: `Resolved IP ${record.address} is forbidden: ${check.reason}`,
          matchedCidr: check.matchedCidr,
          resolvedIps
        };
      }
    }
  }

  // Stage 5 readiness: Select the first valid IP as the pinned IP
  const pinnedIp = resolvedRecords[0].address;

  return {
    allowed: true,
    normalizedUrl: parsedUrl.toString(),
    resolvedIps,
    pinnedIp
  };
}

export interface SafeFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  headers?: Record<string, string>;
  method?: string;
  dnsResolver?: DnsResolverFn;
  allowPrivateForTesting?: boolean;
  allowPrivateRedirects?: boolean;
}

export interface SafeFetchResult {
  statusCode: number;
  statusText: string;
  headers: http.IncomingHttpHeaders;
  data: string;
  url: string;
  pinnedIp: string;
}

/**
 * Stage 5 & 6: Safe HTTP Client with IP Pinning, Redirect Inspection, 5MB Size Cap, 5000ms Timeout
 */
export async function safeFetch(
  targetUrl: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const timeoutMs = options.timeoutMs ?? 5000;
  const maxBytes = options.maxBytes ?? 5 * 1024 * 1024; // 5 MB
  const maxRedirects = options.maxRedirects ?? 3;
  let currentUrl = targetUrl;
  let redirectsFollowed = 0;

  while (redirectsFollowed <= maxRedirects) {
    // Validate target URL through Stages 1-4
    const isRedirectHop = redirectsFollowed > 0;
    const allowPrivate = isRedirectHop
      ? (options.allowPrivateRedirects ?? Boolean(options.allowPrivateForTesting))
      : Boolean(options.allowPrivateForTesting);

    const validation = await validateUrlForSsrf(currentUrl, {
      dnsResolver: options.dnsResolver,
      allowPrivateForTesting: allowPrivate
    });

    if (!validation.allowed || !validation.pinnedIp) {
      const errorCode = validation.error || 'SSRF_BLOCKED';
      const errorMessage = validation.reason ? `${errorCode}: ${validation.reason}` : errorCode;
      const err = new Error(errorMessage);
      (err as unknown as { code: string }).code = errorCode;
      throw err;
    }

    const parsed = new URL(currentUrl);
    const isHttps = parsed.protocol === 'https:';
    const transport = isHttps ? https : http;
    const defaultPort = isHttps ? 443 : 80;
    const port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;
    const pinnedIp = validation.pinnedIp;

    const result = await new Promise<SafeFetchResult | { redirectUrl: string }>((resolve, reject) => {
      let isSettled = false;
      let bytesReceived = 0;
      const chunks: Buffer[] = [];

      // IP Pinning: Connect directly to pinnedIp while sending original Host header and TLS SNI
      const requestOptions: https.RequestOptions = {
        hostname: pinnedIp, // Direct socket connection to pinned IP (anti-DNS rebinding)
        port,
        path: parsed.pathname + parsed.search,
        method: options.method || 'GET',
        headers: {
          Host: parsed.host, // Original Host header
          'User-Agent': 'EyeOfDharma-Collector/1.0',
          Accept: '*/*',
          ...options.headers
        },
        timeout: timeoutMs,
        // For HTTPS, servername provides TLS SNI verification for the original domain
        servername: parsed.hostname
      };

      const req = transport.request(requestOptions, (res) => {
        const statusCode = res.statusCode || 200;

        // Stage 6: Redirect inspection
        if ([301, 302, 303, 307, 308].includes(statusCode) && res.headers.location) {
          req.destroy();
          isSettled = true;
          const nextUrl = new URL(res.headers.location, currentUrl).toString();
          resolve({ redirectUrl: nextUrl });
          return;
        }

        res.on('data', (chunk: Buffer) => {
          bytesReceived += chunk.length;
          // Stage 6: Hard size cap (5MB)
          if (bytesReceived > maxBytes) {
            req.destroy();
            if (!isSettled) {
              isSettled = true;
              const sizeErr = new Error(`PAYLOAD_TOO_LARGE: Response exceeded maximum allowed size of ${maxBytes} bytes`);
              (sizeErr as unknown as { code: string }).code = 'PAYLOAD_TOO_LARGE';
              reject(sizeErr);
            }
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          if (!isSettled) {
            isSettled = true;
            const fullBody = Buffer.concat(chunks).toString('utf8');
            resolve({
              statusCode,
              statusText: res.statusMessage || '',
              headers: res.headers,
              data: fullBody,
              url: currentUrl,
              pinnedIp
            });
          }
        });

        res.on('error', (err) => {
          if (!isSettled) {
            isSettled = true;
            reject(err);
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        if (!isSettled) {
          isSettled = true;
          const timeoutErr = new Error(`REQUEST_TIMEOUT: Request exceeded timeout limit of ${timeoutMs}ms`);
          (timeoutErr as unknown as { code: string }).code = 'REQUEST_TIMEOUT';
          reject(timeoutErr);
        }
      });

      req.on('error', (err) => {
        if (!isSettled) {
          isSettled = true;
          reject(err);
        }
      });

      req.end();
    });

    if ('redirectUrl' in result) {
      redirectsFollowed++;
      if (redirectsFollowed > maxRedirects) {
        const redirectErr = new Error('MAX_REDIRECTS_EXCEEDED: Exceeded 3 redirect hops');
        (redirectErr as unknown as { code: string }).code = 'MAX_REDIRECTS_EXCEEDED';
        throw redirectErr;
      }
      currentUrl = result.redirectUrl;
      continue;
    }

    return result;
  }

  throw new Error('MAX_REDIRECTS_EXCEEDED');
}
