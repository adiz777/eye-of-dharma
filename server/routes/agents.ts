// server/routes/agents.ts
// Multi-Agent investigation run tracking and dispatch endpoints

import { Router } from 'express';
import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { DispatchAgentSchema, validateBody } from '../security/validation.js';
import { recordAuditEvent } from '../security/audit.js';
import type { AgentRunRecord } from '../db/schema.js';

export function createAgentsRouter(db: Database.Database): Router {
  const router = Router();

  // List agent runs
  router.get('/agents/runs', (req, res) => {
    const { case_id, status } = req.query;
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (case_id && typeof case_id === 'string') {
      conditions.push('case_id = ?');
      params.push(case_id);
    }
    if (status && typeof status === 'string') {
      conditions.push('status = ?');
      params.push(status);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const items = db.prepare(`SELECT * FROM agent_runs ${whereClause} ORDER BY started_at DESC`).all(...params) as AgentRunRecord[];

    const parsedItems = items.map((r) => ({
      ...r,
      input_parameters: JSON.parse(r.input_parameters || '{}'),
      execution_plan: r.execution_plan ? JSON.parse(r.execution_plan) : null,
      citations: JSON.parse(r.citations || '[]')
    }));

    res.json({
      success: true,
      items: parsedItems
    });
  });

  // Dispatch agent run
  const handleDispatch = (req: import('express').Request, res: import('express').Response) => {
    const body = req.body;
    const runId = `run-${crypto.randomUUID()}`;
    const inputParamsStr = JSON.stringify({ goal: body.goal, ...body.parameters });

    const stmt = db.prepare(`
      INSERT INTO agent_runs (
        id, case_id, agent_name, status, input_parameters, execution_plan,
        output_summary, token_usage, execution_time_ms, error_message, citations,
        started_at, completed_at
      ) VALUES (
        ?, ?, ?, 'PLANNED', ?, null,
        null, 0, 0, null, '[]',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), null
      )
    `);

    stmt.run(
      runId,
      body.case_id || null,
      body.agent_name,
      inputParamsStr
    );

    recordAuditEvent(db, {
      actor: 'OPERATOR',
      action: 'AGENT_DISPATCHED',
      entity_type: 'AGENT_RUN',
      entity_id: runId,
      details: { agent_name: body.agent_name, goal: body.goal },
      ip_address: req.ip
    });

    const created = db.prepare('SELECT * FROM agent_runs WHERE id = ?').get(runId) as AgentRunRecord;

    res.status(202).json({
      success: true,
      data: {
        ...created,
        input_parameters: JSON.parse(created.input_parameters || '{}'),
        citations: JSON.parse(created.citations || '[]')
      }
    });
  };

  router.post('/agents/dispatch', validateBody(DispatchAgentSchema), handleDispatch);
  router.post('/agents/run', validateBody(DispatchAgentSchema), handleDispatch);

  // Get agent run by ID
  router.get('/agents/runs/:id', (req, res) => {
    const { id } = req.params;
    const run = db.prepare('SELECT * FROM agent_runs WHERE id = ?').get(id) as AgentRunRecord | undefined;

    if (!run) {
      res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Agent run with id '${id}' not found` }
      });
      return;
    }

    res.json({
      success: true,
      data: {
        ...run,
        input_parameters: JSON.parse(run.input_parameters || '{}'),
        execution_plan: run.execution_plan ? JSON.parse(run.execution_plan) : null,
        citations: JSON.parse(run.citations || '[]')
      }
    });
  });

  return router;
}
