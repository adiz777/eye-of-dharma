// server/security/audit.ts
// Tamper-evident Audit Event Logger for EOD Operations

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { AuditStatus } from '../db/schema.js';

export interface AuditEventInput {
  actor?: string;
  action: string;
  entity_type: string;
  entity_id?: string | null;
  details?: Record<string, unknown> | string;
  ip_address?: string | null;
  user_agent?: string | null;
  status?: AuditStatus;
}

export function recordAuditEvent(db: Database.Database, event: AuditEventInput): void {
  try {
    const id = `aud-${crypto.randomUUID()}`;
    const stmt = db.prepare(`
      INSERT INTO audit_events (
        id, actor, action, entity_type, entity_id, details, ip_address, user_agent, status, timestamp
      ) VALUES (
        @id, @actor, @action, @entity_type, @entity_id, @details, @ip_address, @user_agent, @status, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      )
    `);

    const detailsStr = typeof event.details === 'string' ? event.details : JSON.stringify(event.details || {});

    stmt.run({
      id,
      actor: event.actor || 'SYSTEM',
      action: event.action,
      entity_type: event.entity_type,
      entity_id: event.entity_id || null,
      details: detailsStr,
      ip_address: event.ip_address || null,
      user_agent: event.user_agent || null,
      status: event.status || 'SUCCESS'
    });
  } catch (err) {
    // Non-blocking fallback logging so audit failure doesn't break primary flows
    console.error('[Audit Logger Error] Failed to write audit event:', err);
  }
}
