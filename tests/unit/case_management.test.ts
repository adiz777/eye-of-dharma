// tests/unit/case_management.test.ts
// Unit tests for Milestone M4: Schemas, Classification, XSS Sanitization, and Helpers

import { describe, it, expect } from 'vitest';
import {
  CreateCaseSchema,
  UpdateCaseSchema,
  CaseNoteSchema,
  AttachEvidenceSchema,
  EntityTypeEnum,
  CreateCaseEntitySchema,
  CreateCaseRelationshipSchema,
  FootprintQuerySchema
} from '../../server/security/validation.js';
// @ts-expect-error JS module without declaration file
import { formatSha256Pill, formatEvidenceRow, renderSafeMarkdown } from '../../public/js/components/case_workspace.js';
// @ts-expect-error JS module without declaration file
import { classifyFootprintResponse, FOOTPRINT_STATUS, validateFootprintInput } from '../../public/js/components/footprint_ui.js';

describe('M4 Unit Suite: Case Management & TLP Schemas', () => {
  it('CASE-SCHEMA-1: CreateCaseSchema validates title, tlp, classification, and priority', () => {
    const valid = {
      title: 'Operation Aurora Boreal',
      description: 'Baltic power grid monitoring',
      priority: 'HIGH',
      tlp: 'TLP:AMBER',
      classification: 'CONFIDENTIAL',
      lead_analyst: 'DHARMA Coordinator',
      tags: ['SCADA', 'ENERGY']
    };

    const res = CreateCaseSchema.safeParse(valid);
    expect(res.success).toBe(true);
    if (res.success) {
      expect(res.data.title).toBe(valid.title);
      expect(res.data.tlp).toBe('TLP:AMBER');
      expect(res.data.classification).toBe('CONFIDENTIAL');
      expect(res.data.priority).toBe('HIGH');
    }
  });

  it('CASE-SCHEMA-2: CreateCaseSchema accepts severity as an alias for priority', () => {
    const withSeverity = {
      title: 'Ransomware Outbreak 2026',
      severity: 'CRITICAL',
      tlp: 'TLP:RED',
      classification: 'SECRET'
    };

    const res = CreateCaseSchema.safeParse(withSeverity);
    expect(res.success).toBe(true);
    if (res.success) {
      expect(res.data.priority).toBe('CRITICAL');
      expect(res.data.tlp).toBe('TLP:RED');
      expect(res.data.classification).toBe('SECRET');
    }
  });

  it('CASE-SCHEMA-3: CreateCaseSchema rejects short title and unknown properties', () => {
    const shortTitle = { title: 'ab' };
    expect(CreateCaseSchema.safeParse(shortTitle).success).toBe(false);

    const unknownProp = {
      title: 'Valid Case Title',
      hacker_field: 'malicious_input'
    };
    const res = CreateCaseSchema.safeParse(unknownProp);
    expect(res.success).toBe(false);
  });

  it('CASE-SCHEMA-4: UpdateCaseSchema validates status, priority/severity, and tlp updates', () => {
    const valid = {
      status: 'CLOSED',
      severity: 'LOW',
      tlp: 'TLP:CLEAR',
      classification: 'UNCLASSIFIED'
    };

    const res = UpdateCaseSchema.safeParse(valid);
    expect(res.success).toBe(true);
    if (res.success) {
      expect(res.data.status).toBe('CLOSED');
      expect(res.data.priority).toBe('LOW');
      expect(res.data.tlp).toBe('TLP:CLEAR');
    }
  });
});

describe('M4 Unit Suite: Analyst Notes & Evidence Attachment Schemas', () => {
  it('NOTE-SCHEMA-1: CaseNoteSchema accepts note up to 5,000 characters', () => {
    const maxNote = {
      author: 'Lead Investigator',
      content: 'N'.repeat(5000),
      tags: ['IOC', 'C2']
    };

    const res = CaseNoteSchema.safeParse(maxNote);
    expect(res.success).toBe(true);
  });

  it('NOTE-SCHEMA-2: CaseNoteSchema rejects empty or whitespace-only content', () => {
    const empty = { content: '' };
    expect(CaseNoteSchema.safeParse(empty).success).toBe(false);

    const whitespace = { content: '    ' };
    expect(CaseNoteSchema.safeParse(whitespace).success).toBe(false);
  });

  it('NOTE-SCHEMA-3: CaseNoteSchema rejects note exceeding 5,000 characters', () => {
    const oversized = {
      content: 'X'.repeat(5001)
    };
    const res = CaseNoteSchema.safeParse(oversized);
    expect(res.success).toBe(false);
    expect(res.error?.errors[0].message).toContain('5,000 characters');
  });

  it('EVID-SCHEMA-1: AttachEvidenceSchema validates evidence_id and optional notes', () => {
    const valid = {
      evidence_id: 'ev-00000000-0000-0000-0000-000000000001',
      notes: 'Cross-referenced with CISA AA26-081A'
    };
    expect(AttachEvidenceSchema.safeParse(valid).success).toBe(true);

    const missingId = { notes: 'Missing ID' };
    expect(AttachEvidenceSchema.safeParse(missingId).success).toBe(false);
  });
});

describe('M4 Unit Suite: Entity Type Normalization & Graph Schemas', () => {
  it('ENTITY-NORM-1: EntityTypeEnum normalizes IP to IP_ADDRESS', () => {
    const parsed = EntityTypeEnum.safeParse('IP');
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data).toBe('IP_ADDRESS');
    }

    const parsedDirect = EntityTypeEnum.safeParse('IP_ADDRESS');
    expect(parsedDirect.success).toBe(true);
    if (parsedDirect.success) {
      expect(parsedDirect.data).toBe('IP_ADDRESS');
    }
  });

  it('ENTITY-SCHEMA-1: CreateCaseEntitySchema accepts valid entity and normalizes IP', () => {
    const entity = {
      name: 'Primary Ingress IP',
      type: 'IP',
      value: '198.51.100.25',
      risk_score: 75
    };

    const res = CreateCaseEntitySchema.safeParse(entity);
    expect(res.success).toBe(true);
    if (res.success) {
      expect(res.data.type).toBe('IP_ADDRESS');
    }
  });

  it('REL-SCHEMA-1: CreateCaseRelationshipSchema validates relation type and confidence', () => {
    const rel = {
      source_entity_id: 'ent-1',
      target_entity_id: 'ent-2',
      relation_type: 'COMMUNICATES_WITH',
      confidence: 0.85,
      status: 'VERIFIED'
    };

    const res = CreateCaseRelationshipSchema.safeParse(rel);
    expect(res.success).toBe(true);
  });
});

describe('M4 Unit Suite: Footprint Response Classification & Passive Guard', () => {
  it('FP-CLASSIFY-1: Classifies 200 with found: false as NEGATIVE_RESULT with no retry', () => {
    const classified = classifyFootprintResponse(200, {
      success: true,
      found: false,
      records: []
    });

    expect(classified.status).toBe(FOOTPRINT_STATUS.NEGATIVE_RESULT);
    expect(classified.badgeText).toContain('NO RECORDS FOUND');
    expect(classified.badgeClass).toBe('badge-neutral');
    expect(classified.canRetry).toBe(false);
  });

  it('FP-CLASSIFY-2: Classifies 504 / 502 upstream errors as UPSTREAM_FAILURE with retry', () => {
    const classified = classifyFootprintResponse(504, null, {
      code: 'UPSTREAM_DNS_TIMEOUT',
      message: 'Cloudflare DoH timeout'
    });

    expect(classified.status).toBe(FOOTPRINT_STATUS.UPSTREAM_FAILURE);
    expect(classified.badgeText).toContain('504');
    expect(classified.badgeClass).toBe('badge-danger');
    expect(classified.canRetry).toBe(true);
  });

  it('FP-VALIDATE-1: Validates target format by query type', () => {
    expect(validateFootprintInput('DOMAIN', 'valid-domain.com').valid).toBe(true);
    expect(validateFootprintInput('DOMAIN', 'invalid domain').valid).toBe(false);

    expect(validateFootprintInput('IP', '192.168.1.1').valid).toBe(true);
    expect(validateFootprintInput('IP', '999.999.999.999').valid).toBe(false);

    expect(validateFootprintInput('EMAIL', 'analyst@agency.gov').valid).toBe(true);
    expect(validateFootprintInput('EMAIL', 'not-an-email').valid).toBe(false);

    expect(validateFootprintInput('USERNAME', 'x').valid).toBe(false);
    expect(validateFootprintInput('USERNAME', 'threat_actor_44').valid).toBe(true);
  });

  it('FP-SCHEMA-1: FootprintQuerySchema requires confirm_passive = true', () => {
    expect(
      FootprintQuerySchema.safeParse({
        query_type: 'DOMAIN',
        target: 'example.com'
      }).success
    ).toBe(false);

    expect(
      FootprintQuerySchema.safeParse({
        query_type: 'DOMAIN',
        target: 'example.com',
        confirm_passive: false
      }).success
    ).toBe(false);

    expect(
      FootprintQuerySchema.safeParse({
        query_type: 'DOMAIN',
        target: 'example.com',
        confirm_passive: true
      }).success
    ).toBe(true);
  });
});

describe('M4 Unit Suite: Formatting & XSS Sanitization', () => {
  it('FMT-1: formatSha256Pill truncates 64-char hex strings accurately', () => {
    const hash = 'a'.repeat(64);
    const pill = formatSha256Pill(hash);
    expect(pill.short).toBe('aaaaaaaa...aaaaaa');
    expect(pill.full).toBe(hash);

    expect(formatSha256Pill('short').short).toBe('INVALID_HASH');
  });

  it('FMT-2: formatEvidenceRow formats confidence and fingerprint', () => {
    const row = formatEvidenceRow({
      id: 'ev-test-1',
      source_title: 'DNS Resolution A Record',
      source_type: 'DNS_RECORD',
      source_url: 'https://dns.google',
      content_fingerprint: 'b'.repeat(64),
      verification_status: 'Observed',
      confidence_score: 0.95
    });

    expect(row.id).toBe('ev-test-1');
    expect(row.confidence).toBe('95%');
    expect(row.fingerprintShort).toBe('bbbbbbbb...bbbbbb');
  });

  it('XSS-1: renderSafeMarkdown escapes HTML tags while formatting markdown', () => {
    const hostile = '<script>alert(1)</script><img src=x onerror=alert(2)>\n\n**Bold Finding**';
    const rendered = renderSafeMarkdown(hostile);

    expect(rendered).not.toContain('<script>');
    expect(rendered).not.toContain('<img src=x');
    expect(rendered).toContain('&lt;script&gt;');
    expect(rendered).toContain('&lt;img src=x');
    expect(rendered).toContain('<strong>Bold Finding</strong>');
  });

  it('XSS-2: renderSafeMarkdown blocks javascript: and data: pseudo-protocols in links', () => {
    const linkAttack = '[Exploit](javascript:stealCookies()) and [Valid Link](https://cisa.gov)';
    const rendered = renderSafeMarkdown(linkAttack);

    expect(rendered).not.toContain('<a href="javascript:');
    expect(rendered).toContain('<a href="https://cisa.gov"');
  });
});
