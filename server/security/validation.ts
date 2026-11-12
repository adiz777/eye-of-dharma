// server/security/validation.ts
// Zod schemas and validation middleware for EYE OF DHARMA API

import { z } from 'zod';
import type { Request, Response, NextFunction } from 'express';

// Enums for TLP and Classification
export const TlpEnum = z.enum(['TLP:WHITE', 'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']);
export const ClassificationEnum = z.enum(['UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET']);

// 1. Case Schemas
export const CreateCaseSchema = z.object({
  title: z.string().trim().min(3, 'Title must be at least 3 characters').max(200),
  description: z.string().trim().max(5000).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(), // Alias for priority
  tlp: TlpEnum.default('TLP:AMBER'),
  classification: ClassificationEnum.default('UNCLASSIFIED'),
  lead_analyst: z.string().trim().min(1).max(100).default('Analyst'),
  tags: z.array(z.string().trim().max(50)).max(20).default([]),
  summary: z.string().trim().max(2000).optional(),
  is_synthetic: z.boolean().default(false)
}).strict().transform((data) => ({
  ...data,
  priority: data.priority || data.severity || 'MEDIUM'
}));

export const UpdateCaseSchema = z.object({
  title: z.string().trim().min(3).max(200).optional(),
  description: z.string().trim().max(5000).optional(),
  status: z.enum(['OPEN', 'ACTIVE', 'IN_PROGRESS', 'PENDING_REVIEW', 'CLOSED', 'ARCHIVED']).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  tlp: TlpEnum.optional(),
  classification: ClassificationEnum.optional(),
  lead_analyst: z.string().trim().max(100).optional(),
  tags: z.array(z.string().trim().max(50)).max(20).optional(),
  summary: z.string().trim().max(2000).optional()
}).strict().transform((data) => ({
  ...data,
  priority: data.priority || data.severity
}));

// 2. Evidence Ledger Schemas
export const IngestEvidenceSchema = z.object({
  case_id: z.string().trim().min(1).optional().nullable(),
  source_url: z.string().url('Valid URL required').max(1000),
  source_type: z.enum([
    'USGS_EARTHQUAKE', 'NASA_EONET', 'CISA_KEV', 'CISA_ADVISORY',
    'CRT_SH', 'DNS_RECORD', 'RDAP_REGISTRATION', 'RSS_FEED',
    'MANUAL_ENTRY', 'AGENT_RESEARCH', 'SYNTHETIC_SEED'
  ]),
  source_title: z.string().trim().min(1).max(300),
  raw_content: z.string().min(1, 'Raw content cannot be empty'),
  parsed_content: z.record(z.unknown()).optional().nullable(),
  verification_status: z.enum([
    'Observed', 'Source-reported', 'Corroborated', 'Inferred', 'Unverified', 'Stale'
  ]).default('Unverified'),
  confidence_score: z.number().min(0.0).max(1.0).default(0.50),
  published_at: z.string().optional().nullable(),
  notes: z.string().max(2000).optional().nullable(),
  is_synthetic: z.boolean().default(false)
}).strict();

export const AttachEvidenceSchema = z.object({
  evidence_id: z.string().trim().min(1, 'Evidence ID is required'),
  notes: z.string().trim().max(1000).optional().nullable()
}).strict();
export const AttachExistingEvidenceSchema = AttachEvidenceSchema;

// 3. Entity Schemas
export const EntityTypeEnum = z.preprocess(
  (val) => (val === 'IP' ? 'IP_ADDRESS' : val),
  z.enum([
    'DOMAIN', 'IP_ADDRESS', 'EMAIL', 'ACTOR', 'ORGANIZATION',
    'MALWARE', 'VULNERABILITY', 'GEOLOCATION', 'INFRASTRUCTURE',
    'CERTIFICATE', 'CRYPTO_WALLET', 'FILE_HASH'
  ])
);

export const CreateEntitySchema = z.object({
  case_id: z.string().trim().min(1).optional().nullable(),
  name: z.string().trim().min(1).max(200),
  type: EntityTypeEnum,
  value: z.string().trim().min(1).max(500),
  risk_score: z.number().int().min(0).max(100).default(0),
  metadata: z.record(z.unknown()).default({}),
  is_synthetic: z.boolean().default(false)
}).strict();

export const CreateCaseEntitySchema = z.object({
  name: z.string().trim().min(1, 'Entity name is required').max(200),
  type: EntityTypeEnum,
  value: z.string().trim().min(1, 'Entity value is required').max(500),
  risk_score: z.number().int().min(0).max(100).default(0),
  metadata: z.record(z.unknown()).default({}),
  is_synthetic: z.boolean().default(false)
}).strict();

// 4. Relationship Schemas
export const CreateRelationshipSchema = z.object({
  source_entity_id: z.string().trim().min(1),
  target_entity_id: z.string().trim().min(1),
  relation_type: z.enum([
    'RESOLVES_TO', 'COMMUNICATES_WITH', 'ATTRIBUTED_TO', 'EXPLOITS',
    'HOSTED_ON', 'REGISTERED_BY', 'AFFILIATED_WITH', 'ASSOCIATED_WITH',
    'MENTIONS', 'SUBDOMAIN_OF', 'CERTIFIED_BY'
  ]),
  confidence: z.number().min(0.0).max(1.0).default(0.50),
  evidence_id: z.string().trim().min(1).optional().nullable(),
  status: z.enum(['VERIFIED', 'INFERRED', 'HYPOTHESIS']).default('INFERRED'),
  notes: z.string().max(1000).optional().nullable(),
  is_synthetic: z.boolean().default(false)
}).strict();

export const CreateCaseRelationshipSchema = CreateRelationshipSchema;

// 4b. Analyst Notes Schemas
export const CaseNoteSchema = z.object({
  content: z.string().trim().min(1, 'Note content cannot be empty').max(5000, 'Note cannot exceed 5,000 characters'),
  author: z.string().trim().min(1).max(100).default('Analyst'),
  tags: z.array(z.string().trim().max(50)).max(10).default([]),
  parent_note_id: z.string().trim().min(1).optional().nullable()
}).strict();
export const CreateCaseNoteSchema = CaseNoteSchema;
export const CreateAnalystNoteSchema = CaseNoteSchema;

// 5. Threat Indicator Schemas
export const CreateThreatIndicatorSchema = z.object({
  indicator_type: z.enum(['IPV4', 'IPV6', 'DOMAIN', 'URL', 'SHA256', 'MD5', 'CVE', 'EMAIL', 'MUTEX']),
  indicator_value: z.string().trim().min(1).max(500),
  threat_actor: z.string().trim().max(200).optional().nullable(),
  campaign: z.string().trim().max(200).optional().nullable(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
  confidence: z.number().min(0.0).max(1.0).default(0.70),
  source: z.string().trim().min(1).max(200),
  tags: z.array(z.string().trim().max(50)).default([]),
  description: z.string().trim().max(2000).optional().nullable(),
  is_synthetic: z.boolean().default(false)
}).strict();

// 6. Watchlist Schemas
export const CreateWatchlistSchema = z.object({
  name: z.string().trim().min(1).max(200),
  description: z.string().trim().max(1000).optional().nullable(),
  target_type: z.enum(['DOMAIN', 'IP_RANGE', 'CVE', 'KEYWORD', 'ASN', 'ACTOR']),
  pattern: z.string().trim().min(1).max(500),
  alert_severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
  is_active: z.boolean().default(true),
  is_synthetic: z.boolean().default(false)
}).strict();

export const UpdateWatchlistSchema = z.object({
  is_active: z.boolean()
}).strict();

// 7. Digital Footprint Schema
export const FootprintQuerySchema = z.object({
  query_type: z.enum(['DOMAIN', 'IP', 'EMAIL', 'USERNAME', 'CERTIFICATE']).optional(),
  target_type: z.enum(['DOMAIN', 'IP', 'EMAIL', 'USERNAME', 'CERTIFICATE']).optional(),
  target: z.string().trim().min(1).max(255).optional(),
  target_value: z.string().trim().min(1).max(255).optional(),
  confirm_passive: z.literal(true, {
    errorMap: () => ({ message: 'Explicit confirmation of passive-only execution required.' })
  }),
  case_id: z.string().trim().min(1).optional().nullable()
}).strict().superRefine((data, ctx) => {
  const qt = data.query_type || data.target_type;
  const tg = data.target || data.target_value;
  if (!qt) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'query_type or target_type is required', path: ['query_type'] });
  }
  if (!tg || tg.trim().length === 0) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'target or target_value cannot be empty', path: ['target'] });
  }
}).transform((data) => {
  const qt = (data.query_type || data.target_type)!;
  const tg = (data.target || data.target_value)!.trim();
  return {
    query_type: qt,
    target_type: qt,
    target: tg,
    target_value: tg,
    confirm_passive: data.confirm_passive,
    case_id: data.case_id
  };
});

// 8. Terminal Command Schema
export const TerminalCommandSchema = z.object({
  command: z.string().trim().min(1).max(200)
}).strict();

// 9. Agent Dispatch Schema
export const DispatchAgentSchema = z.object({
  case_id: z.string().trim().min(1).optional().nullable(),
  agent_name: z.enum(['DHARMA', 'NETRA', 'CIPHER', 'SENTINEL', 'ATLAS', 'VERITAS', 'SCRIBE']),
  goal: z.string().trim().min(1).max(1000),
  parameters: z.record(z.unknown()).default({})
}).strict();

// Generic Validation Middleware
export function validateBody<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parseResult = schema.safeParse(req.body);
    if (!parseResult.success) {
      const details = parseResult.error.errors.map((e) => ({
        path: e.path.join('.'),
        message: e.message
      }));
      res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request payload validation failed',
          details
        }
      });
      return;
    }
    req.body = parseResult.data;
    next();
  };
}

export const EntityQuerySchema = z.object({
  query_type: z.enum(['PERSON', 'ORGANIZATION', 'USERNAME']),
  target: z.string().trim().min(2).max(120),
  confirm_passive: z.literal(true),
  // Explicit statement that the lookup is lawful, proportionate and (for PERSON) about a public figure or an authorised subject.
  confirm_lawful_purpose: z.literal(true),
  case_id: z.string().trim().min(1).optional().nullable()
}).strict();
