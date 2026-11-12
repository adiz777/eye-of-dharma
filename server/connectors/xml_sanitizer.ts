// server/connectors/xml_sanitizer.ts
// Zero-dependency XML/HTML parser, XXE guard, and content sanitizer

/**
 * Strips all XML/HTML markup, decodes standard HTML entities, and collapses whitespace.
 */
export function sanitizeToPlainText(input: string): string {
  if (!input || typeof input !== 'string') return '';

  return input
    // Remove scripts and styles with their inner content
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    // Remove CDATA markers
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/gi, '$1')
    // Remove all remaining HTML tags
    .replace(/<[^>]+>/g, ' ')
    // Unescape XML/HTML entities
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    // Normalize whitespace
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Strips dangerous HTML elements, protocols, and event handlers while preserving safe semantic tags.
 */
export function sanitizeSafeHtml(input: string): string {
  if (!input || typeof input !== 'string') return '';

  // 1. Strip CDATA markers
  let clean = input.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/gi, '$1');

  // 2. Remove hostile tags and their inner contents
  const dangerousTags = ['script', 'style', 'iframe', 'frame', 'object', 'embed', 'applet', 'meta', 'link', 'form', 'svg', 'base'];
  for (const tag of dangerousTags) {
    const reg = new RegExp(`<${tag}\\b[^<]*(?:(?!<\\/${tag}>)<[^<]*)*<\\/${tag}>`, 'gi');
    clean = clean.replace(reg, '');
    clean = clean.replace(new RegExp(`<${tag}\\b[^>]*\\/?>`, 'gi'), '');
  }

  // 3. Strip all inline event handlers (onload, onerror, onclick, etc.)
  clean = clean.replace(/\s+on[a-zA-Z]+\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)/gi, '');

  // 4. Strip dangerous protocols (javascript:, vbscript:, data:)
  clean = clean.replace(/(href|src)\s*=\s*(['"])\s*(?:javascript|vbscript|data):[\s\S]*?\2/gi, '$1="#"');

  return clean.trim();
}

/**
 * Extracts inner text of an XML element by tag name, handling CDATA and unescaping entities.
 */
export function extractXmlTag(xmlFragment: string, tagName: string): string | null {
  // Matches <tag>content</tag> or <prefix:tag>content</prefix:tag>
  const escapedTag = tagName.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
  const regex = new RegExp(`<(?:[a-zA-Z0-9_-]+:)?${escapedTag}(?:\\s+[^>]*)?>([\\s\\S]*?)<\\/(?:[a-zA-Z0-9_-]+:)?${escapedTag}>`, 'i');
  const match = xmlFragment.match(regex);
  if (!match || !match[1]) return null;

  let val = match[1].trim();
  // Unwrap CDATA if present
  const cdataMatch = val.match(/^<!\[CDATA\[([\s\S]*?)\]\]>$/i);
  if (cdataMatch) {
    val = cdataMatch[1];
  }
  return val;
}

/**
 * Extracts attribute value from an XML element (e.g., <link href="..." />).
 */
export function extractXmlAttr(xmlFragment: string, tagName: string, attrName: string): string | null {
  const escapedTag = tagName.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
  const regex = new RegExp(`<(?:[a-zA-Z0-9_-]+:)?${escapedTag}\\s+[^>]*${attrName}=['"]([^'"]+)['"][^>]*>`, 'i');
  const match = xmlFragment.match(regex);
  return match ? match[1] : null;
}

/**
 * Anti-XXE Validator: Rejects XML payloads containing entity expansions or external entities.
 */
export function assertSafeXml(xml: string): void {
  if (/<!ENTITY/i.test(xml)) {
    throw new Error('XXE_ATTACK_DETECTED: XML entity definitions are forbidden.');
  }
  if (/<!DOCTYPE/i.test(xml) && !/<!DOCTYPE\s+html/i.test(xml)) {
    throw new Error('DTD_FORBIDDEN: Custom XML DTD doctype declarations are forbidden.');
  }
}
