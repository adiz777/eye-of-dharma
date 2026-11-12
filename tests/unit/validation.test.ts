// tests/unit/validation.test.ts
// Unit tests for Zod schema validation across all EOD DTOs

import { describe, it, expect } from 'vitest';
import {
  CreateCaseSchema,
  UpdateCaseSchema,
  IngestEvidenceSchema,
  CreateEntitySchema,
  CreateRelationshipSchema,
  CreateThreatIndicatorSchema,
  CreateWatchlistSchema,
  FootprintQuerySchema,
  TerminalCommandSchema,
  DispatchAgentSchema
} from '../../server/security/validation.js';

describe('Validation Schemas - Case Management', () => {
  it('should accept valid CreateCase payload with defaults', () => {
    const valid = {
      title: 'Project Aurora Breach'
    };
    const res = CreateCaseSchema.safeParse(valid);
    expect(res.success).toBe(true);
    if (res.success) {
      expect(res.data.priority).toBe('MEDIUM');
      expect(res.data.lead_analyst).toBe('Analyst');
      expect(res.data.tags).toEqual([]);
      expect(res.data.is_synthetic).toBe(false);
    }
  });

  it('should reject CreateCase with short title or invalid priority', () => {
    const shortTitle = { title: 'ab' };
    expect(CreateCaseSchema.safeParse(shortTitle).success).toBe(false);

    const invalidPriority = { title: 'Valid Title', priority: 'URGENT' };
    expect(CreateCaseSchema.safeParse(invalidPriority).success).toBe(false);
  });

  it('should reject unknown extra properties due to strict mode', () => {
    const extraFields = {
      title: 'Valid Case Title',
      unauthorized_injection: 'DROP TABLE cases'
    };
    const res = CreateCaseSchema.safeParse(extraFields);
    expect(res.success).toBe(false);
  });

  it('should validate UpdateCaseSchema partial updates', () => {
    const validUpdate = {
      status: 'IN_PROGRESS',
      priority: 'CRITICAL',
      summary: 'Updated summary after initial triage'
    };
    expect(UpdateCaseSchema.safeParse(validUpdate).success).toBe(true);

    const invalidStatus = { status: 'DELETED' };
    expect(UpdateCaseSchema.safeParse(invalidStatus).success).toBe(false);
  });
});

describe('Validation Schemas - Evidence Ledger', () => {
  it('should accept valid IngestEvidence payload', () => {
    const valid = {
      source_url: 'https://cisa.gov/advisories/aa26-081a',
      source_type: 'CISA_ADVISORY',
      source_title: 'CISA Alert AA26-081A',
      raw_content: '{"vulnerabilities":["CVE-2026-1189"]}',
      confidence_score: 0.95
    };
    const res = IngestEvidenceSchema.safeParse(valid);
    expect(res.success).toBe(true);
    if (res.success) {
      expect(res.data.verification_status).toBe('Unverified');
    }
  });

  it('should reject invalid URL or empty raw_content', () => {
    const invalidUrl = {
      source_url: 'not-a-valid-url',
      source_type: 'RSS_FEED',
      source_title: 'News article',
      raw_content: 'Some text'
    };
    expect(IngestEvidenceSchema.safeParse(invalidUrl).success).toBe(false);

    const emptyContent = {
      source_url: 'https://example.com/news',
      source_type: 'RSS_FEED',
      source_title: 'News article',
      raw_content: ''
    };
    expect(IngestEvidenceSchema.safeParse(emptyContent).success).toBe(false);
  });

  it('should reject confidence_score outside [0.0, 1.0]', () => {
    const invalidScore = {
      source_url: 'https://example.com/item',
      source_type: 'MANUAL_ENTRY',
      source_title: 'Note',
      raw_content: 'Evidence note',
      confidence_score: 1.5
    };
    expect(IngestEvidenceSchema.safeParse(invalidScore).success).toBe(false);
  });
});

describe('Validation Schemas - Entities & Relationships', () => {
  it('should accept valid CreateEntity payload and validate risk score bounds', () => {
    const validEntity = {
      name: 'APT-29 (Cozy Bear)',
      type: 'ACTOR',
      value: 'APT-29',
      risk_score: 85
    };
    expect(CreateEntitySchema.safeParse(validEntity).success).toBe(true);

    const outOfBoundsRisk = {
      name: 'Bad Entity',
      type: 'IP_ADDRESS',
      value: '1.2.3.4',
      risk_score: 150
    };
    expect(CreateEntitySchema.safeParse(outOfBoundsRisk).success).toBe(false);
  });

  it('should accept valid CreateRelationship payload and reject invalid relation types', () => {
    const validRel = {
      source_entity_id: 'ent-1',
      target_entity_id: 'ent-2',
      relation_type: 'RESOLVES_TO',
      confidence: 0.99,
      status: 'VERIFIED'
    };
    expect(CreateRelationshipSchema.safeParse(validRel).success).toBe(true);

    const invalidType = {
      source_entity_id: 'ent-1',
      target_entity_id: 'ent-2',
      relation_type: 'FRIENDS_WITH'
    };
    expect(CreateRelationshipSchema.safeParse(invalidType).success).toBe(false);
  });
});

describe('Validation Schemas - Threat Indicators & Watchlists', () => {
  it('should accept valid ThreatIndicator and Watchlist payloads', () => {
    const threat = {
      indicator_type: 'DOMAIN',
      indicator_value: 'bad-domain.xyz',
      source: 'CISA',
      severity: 'HIGH'
    };
    expect(CreateThreatIndicatorSchema.safeParse(threat).success).toBe(true);

    const watchlist = {
      name: 'Tor Exit Nodes',
      target_type: 'IP_RANGE',
      pattern: '185.220.*',
      alert_severity: 'HIGH'
    };
    expect(CreateWatchlistSchema.safeParse(watchlist).success).toBe(true);
  });
});

describe('Validation Schemas - Footprint, Terminal, & Agents', () => {
  it('should require confirm_passive: true on footprint query', () => {
    const withoutConfirm = {
      query_type: 'DOMAIN',
      target: 'example.com'
    };
    expect(FootprintQuerySchema.safeParse(withoutConfirm).success).toBe(false);

    const withConfirm = {
      query_type: 'DOMAIN',
      target: 'example.com',
      confirm_passive: true
    };
    expect(FootprintQuerySchema.safeParse(withConfirm).success).toBe(true);
  });

  it('should validate Terminal command string', () => {
    expect(TerminalCommandSchema.safeParse({ command: 'help' }).success).toBe(true);
    expect(TerminalCommandSchema.safeParse({ command: '' }).success).toBe(false);
  });

  it('should validate DispatchAgent personas', () => {
    const validDharma = {
      agent_name: 'DHARMA',
      goal: 'Coordinate initial triage'
    };
    expect(DispatchAgentSchema.safeParse(validDharma).success).toBe(true);

    const invalidAgent = {
      agent_name: 'UNKNOWN_BOT',
      goal: 'Test'
    };
    expect(DispatchAgentSchema.safeParse(invalidAgent).success).toBe(false);
  });
});
