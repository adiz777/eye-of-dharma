// public/js/components/case_workspace.js
// 6-Tab Case Investigation Workspace Shell with Full API Wiring, Notes Immutability & Custody Trail

export const WORKSPACE_TABS = [
  { id: 'overview', title: 'Overview', icon: '📄' },
  { id: 'evidence', title: 'Evidence Ledger', icon: '🗄️' },
  { id: 'graph', title: 'Entities & Graph', icon: '🕸️' },
  { id: 'notes', title: 'Analyst Notes', icon: '📝' },
  { id: 'runs', title: 'Agent Runs', icon: '⚡' },
  { id: 'custody', title: 'Chain of Custody', icon: '🛡️' }
];

/**
 * Truncates 64-char SHA-256 for display while preserving verification integrity
 */
export function formatSha256Pill(hash) {
  if (!hash || typeof hash !== 'string' || hash.length !== 64) {
    return { short: 'INVALID_HASH', full: hash || '' };
  }
  return {
    short: `${hash.slice(0, 8)}...${hash.slice(-6)}`,
    full: hash
  };
}

/**
 * Formats evidence record for rendering
 */
export function formatEvidenceRow(ev) {
  const pill = formatSha256Pill(ev.content_fingerprint || ev.fingerprintFull);
  return {
    id: ev.id,
    title: ev.source_title || ev.title || 'Untitled Evidence',
    type: ev.source_type || ev.type,
    url: ev.source_url || ev.url,
    status: ev.verification_status || ev.status || 'Unverified',
    confidence: typeof ev.confidence === 'string'
      ? ev.confidence
      : Math.round((ev.confidence_score !== undefined ? ev.confidence_score : 0.5) * 100) + '%',
    retrievedAt: ev.retrieved_at || ev.retrievedAt,
    fingerprintShort: pill.short,
    fingerprintFull: pill.full,
    rawContent: ev.raw_content || ev.rawContent
  };
}

/**
 * Lightweight XSS-Safe Markdown Parser for Analyst Notes
 */
export function renderSafeMarkdown(content) {
  if (!content) return '';
  let safe = String(content)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  // Code blocks
  safe = safe.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (_m, lang, code) => {
    return `<pre class="code-block ${lang ? 'lang-' + lang : ''}"><code>${code.trim()}</code></pre>`;
  });

  // Inline code
  safe = safe.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

  // Blockquotes
  safe = safe.replace(/^>\s?(.*)$/gm, '<blockquote class="note-quote">$1</blockquote>');

  // Headers
  safe = safe.replace(/^### (.*$)/gm, '<h4 class="note-h3">$1</h4>');
  safe = safe.replace(/^## (.*$)/gm, '<h3 class="note-h2">$1</h3>');
  safe = safe.replace(/^# (.*$)/gm, '<h2 class="note-h1">$1</h2>');

  // Bold & Italic
  safe = safe.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  safe = safe.replace(/\*([^*]+)\*/g, '<em>$1</em>');

  // Links (only http/https)
  safe = safe.replace(/\[([^\]]+)\]\((https?:\/\/[^\s'")]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" class="note-link">$1</a>');

  // Paragraph breaks
  safe = safe.replace(/\n\n+/g, '</p><p class="note-p">');
  return `<p class="note-p">${safe}</p>`;
}

/**
 * Case Workspace State Controller
 */
export class CaseWorkspaceController {
  constructor(caseId, options = {}) {
    this.caseId = caseId;
    this.baseUrl = options.baseUrl || '/api/v1';
    this.activeTab = 'overview';
    this.caseData = null;
    this.evidence = [];
    this.entities = [];
    this.graphData = { nodes: [], edges: [] };
    this.notes = [];
    this.runs = [];
    this.custody = [];
    this.evidenceFilter = { type: 'ALL', status: 'ALL', q: '' };
    this.activeParentNoteId = null;
    this.onStateChange = options.onStateChange || (() => {});
  }

  async load() {
    try {
      const [caseRes, evidenceRes, notesRes, runsRes, custodyRes, graphRes] = await Promise.all([
        fetch(`${this.baseUrl}/cases/${this.caseId}`).then((r) => r.json()).catch(() => null),
        fetch(`${this.baseUrl}/cases/${this.caseId}/evidence`).then((r) => r.json()).catch(() => null),
        fetch(`${this.baseUrl}/cases/${this.caseId}/notes`).then((r) => r.json()).catch(() => null),
        fetch(`${this.baseUrl}/cases/${this.caseId}/runs`).then((r) => r.json()).catch(() => null),
        fetch(`${this.baseUrl}/cases/${this.caseId}/custody`).then((r) => r.json()).catch(() => null),
        fetch(`${this.baseUrl}/cases/${this.caseId}/graph`).then((r) => r.json()).catch(() => null)
      ]);

      this.caseData = caseRes?.data || caseRes;
      this.evidence = (evidenceRes?.data || evidenceRes?.items || []).map(formatEvidenceRow);
      this.notes = notesRes?.items || [];
      this.runs = runsRes?.items || [];
      this.custody = custodyRes?.custody_chain || [];
      this.graphData = graphRes?.elements || graphRes || { nodes: [], edges: [] };
      this.entities = graphRes?.nodes || graphRes?.elements?.nodes || [];
      this.onStateChange();
    } catch (err) {
      console.error('[Case Workspace] Failed to load case:', err);
    }
  }

  switchTab(tabId) {
    if (WORKSPACE_TABS.some((t) => t.id === tabId)) {
      this.activeTab = tabId;
      this.onStateChange();
    }
  }

  async appendNote(content, author = 'Analyst', parentNoteId = null) {
    if (!content || !content.trim() || content.trim().length > 5000) {
      return false;
    }
    try {
      const res = await fetch(`${this.baseUrl}/cases/${this.caseId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: content.trim(),
          author: author || 'Analyst',
          parent_note_id: parentNoteId || null
        })
      });
      const data = await res.json();
      if (data.success) {
        this.activeParentNoteId = null;
        await this.load();
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  async attachEvidence(evidenceId, notes = null) {
    if (!evidenceId) return false;
    try {
      const res = await fetch(`${this.baseUrl}/cases/${this.caseId}/evidence/attach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence_id: evidenceId, notes })
      });
      const data = await res.json();
      if (data.success) {
        await this.load();
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  async copyHashToClipboard(fullHash) {
    if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(fullHash);
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }
}

/**
 * DOM Mounting helper
 */
export function mountCaseWorkspace(containerEl, caseId = 'case-00000000-0000-0000-0000-000000000001', options = {}) {
  if (typeof document === 'undefined') return;

  const controller = new CaseWorkspaceController(caseId, options);
  const wrapper = document.createElement('div');
  wrapper.className = 'case-workspace-container';

  function render() {
    const c = controller.caseData || {
      id: caseId,
      title: 'Operation Arctic Phoenix',
      description: 'Targeted SCADA reconnaissance and credential staging across Nordic energy grid assets.',
      status: 'OPEN',
      priority: 'CRITICAL',
      tlp: 'TLP:AMBER',
      classification: 'UNCLASSIFIED'
    };

    const metrics = c.metrics || {
      evidenceCount: controller.evidence.length,
      entityCount: controller.entities.length,
      notesCount: controller.notes.length,
      runsCount: controller.runs.length
    };

    wrapper.innerHTML = `
      <!-- Case Header -->
      <div class="card" style="margin-bottom:12px;">
        <div class="card-header">
          <div>
            <span class="badge badge-critical" style="margin-right:6px;">${c.priority || 'CRITICAL'}</span>
            <span class="badge badge-gold" style="margin-right:6px;">${c.tlp || 'TLP:AMBER'}</span>
            <span class="badge badge-neutral">${c.classification || 'UNCLASSIFIED'}</span>
            <h2 style="font-size:16px; font-weight:700; color:var(--text-high); margin-top:6px;">${c.title}</h2>
          </div>
          <div style="font-family:var(--font-mono); font-size:11px; color:var(--accent-cyan);">
            CASE_ID: ${c.id}
          </div>
        </div>
        <div style="font-size:12px; color:var(--text-medium); line-height:1.4;">
          ${c.description || 'No description provided.'}
        </div>
      </div>

      <!-- 6 Tabs Navigation -->
      <div class="workspace-tabs" role="tablist">
        ${WORKSPACE_TABS.map(
          (t) => `
          <button class="workspace-tab ${controller.activeTab === t.id ? 'active' : ''}" data-tab="${t.id}" role="tab" aria-selected="${controller.activeTab === t.id}">
            <span>${t.icon}</span>
            <span>${t.title}</span>
            ${t.id === 'evidence' ? `<span class="badge badge-info" style="margin-left:4px;">${metrics.evidenceCount}</span>` : ''}
            ${t.id === 'notes' ? `<span class="badge badge-neutral" style="margin-left:4px;">${metrics.notesCount}</span>` : ''}
          </button>
        `
        ).join('')}
      </div>

      <!-- Tab Content Panes -->
      <div class="workspace-pane">
        ${renderActiveTab(c, metrics)}
      </div>

      <!-- Raw Evidence Viewer Modal -->
      <div id="raw-modal-container"></div>
    `;

    bindEvents();
  }

  function renderActiveTab(c, metrics) {
    switch (controller.activeTab) {
      case 'overview':
        return `
          <div class="card-grid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:12px;">
            <div class="card font-mono">
              <div style="font-size:11px; color:var(--text-muted);">EVIDENCE ITEMS</div>
              <div style="font-size:22px; font-weight:700; color:var(--accent-cyan); margin-top:4px;">${metrics.evidenceCount}</div>
            </div>
            <div class="card font-mono">
              <div style="font-size:11px; color:var(--text-muted);">GRAPH ENTITIES</div>
              <div style="font-size:22px; font-weight:700; color:var(--status-verified); margin-top:4px;">${metrics.entityCount}</div>
            </div>
            <div class="card font-mono">
              <div style="font-size:11px; color:var(--text-muted);">ANALYST NOTES</div>
              <div style="font-size:22px; font-weight:700; color:var(--accent-gold); margin-top:4px;">${metrics.notesCount}</div>
            </div>
            <div class="card font-mono">
              <div style="font-size:11px; color:var(--text-muted);">AGENT RUNS</div>
              <div style="font-size:22px; font-weight:700; color:var(--text-high); margin-top:4px;">${metrics.runsCount}</div>
            </div>
          </div>

          <div class="card-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap:12px;">
            <div class="card font-mono">
              <div class="card-title">Case Metadata</div>
              <div style="margin-top:12px; font-size:12px; display:flex; flex-direction:column; gap:6px;">
                <div><span style="color:var(--text-muted)">STATUS:</span> <strong style="color:var(--status-verified)">${c.status || 'OPEN'}</strong></div>
                <div><span style="color:var(--text-muted)">LEAD ANALYST:</span> <strong>${c.lead_analyst || 'DHARMA Coordinator'}</strong></div>
                <div><span style="color:var(--text-muted)">TLP:</span> <strong>${c.tlp || 'TLP:AMBER'}</strong></div>
                <div><span style="color:var(--text-muted)">CLASSIFICATION:</span> <strong>${c.classification || 'UNCLASSIFIED'}</strong></div>
                <div><span style="color:var(--text-muted)">CREATED:</span> <strong>${c.created_at || 'N/A'}</strong></div>
              </div>
            </div>
            <div class="card">
              <div class="card-title font-mono">Investigation Summary</div>
              <p style="margin-top:8px; font-size:12px; color:var(--text-medium); line-height:1.5;">
                ${c.summary || c.description || 'Active multi-source OSINT & CTI investigation.'}
              </p>
            </div>
          </div>
        `;

      case 'evidence':
        return `
          <div class="card font-mono">
            <div class="card-header" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
              <span class="card-title">Immutable Evidence Ledger</span>
              <span class="text-muted" style="font-size:11px;">ENGINE-LEVEL IMMUTABLE TRIGGERS ACTIVE</span>
            </div>
            <div style="overflow-x:auto; margin-top:8px;">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>EVIDENCE ID</th>
                    <th>SOURCE TITLE</th>
                    <th>TYPE</th>
                    <th>STATUS</th>
                    <th>CONF</th>
                    <th>SHA-256 FINGERPRINT</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  ${
                    controller.evidence.length === 0
                      ? `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">No evidence records attached yet.</td></tr>`
                      : controller.evidence
                          .map(
                            (e) => `
                        <tr>
                          <td style="color:var(--accent-cyan); font-weight:600;">${e.id.slice(0, 10)}</td>
                          <td style="color:var(--text-high); font-weight:600;">${e.title}</td>
                          <td><span class="badge badge-info">${e.type}</span></td>
                          <td><span class="badge badge-${e.status === 'Observed' ? 'verified' : 'hypothesis'}">${e.status}</span></td>
                          <td style="color:var(--text-muted);">${e.confidence}</td>
                          <td>
                            <button class="hash-pill" data-full-hash="${e.fingerprintFull}" title="Click to copy full hash">
                              📋 ${e.fingerprintShort}
                            </button>
                          </td>
                          <td>
                            <button class="btn btn-secondary btn-view-raw" data-id="${e.id}" style="padding:2px 6px; font-size:10px;">VIEW RAW</button>
                          </td>
                        </tr>
                      `
                          )
                          .join('')
                  }
                </tbody>
              </table>
            </div>
          </div>
        `;

      case 'graph':
        const edges = controller.graphData?.edges || [];
        const nodes = controller.graphData?.nodes || [];
        return `
          <div class="card font-mono" style="min-height:350px;">
            <div class="card-header" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
              <span class="card-title">Case Relationship Topology</span>
              <div style="display:flex; gap:10px; font-size:11px;">
                <span style="color:#00E5FF;">● VERIFIED (Solid Cyan)</span>
                <span style="color:#FFA726;">- - INFERRED (Dashed Amber)</span>
                <span style="color:#D4AF37;">··· HYPOTHESIS (Dotted Gold)</span>
              </div>
            </div>
            <div style="padding:12px; display:flex; gap:16px; font-size:12px; color:var(--text-muted); border-bottom:1px solid var(--border-color);">
              <div>NODES: <strong style="color:var(--text-high);">${nodes.length}</strong></div>
              <div>RELATIONSHIPS: <strong style="color:var(--text-high);">${edges.length}</strong></div>
            </div>
            <div style="padding:12px; overflow-x:auto;">
              ${
                edges.length === 0
                  ? `<div style="text-align:center; padding:20px; color:var(--text-muted);">No entity relationships linked to this case yet.</div>`
                  : `
                <table class="data-table">
                  <thead>
                    <tr><th>SOURCE</th><th>RELATION</th><th>TARGET</th><th>STATUS</th><th>CONF</th></tr>
                  </thead>
                  <tbody>
                    ${edges
                      .map((ed) => {
                        const d = ed.data || ed;
                        const color = d.status === 'VERIFIED' ? '#00E5FF' : d.status === 'HYPOTHESIS' ? '#D4AF37' : '#FFA726';
                        return `
                          <tr>
                            <td style="color:var(--text-high); font-weight:600;">${d.source}</td>
                            <td style="color:${color}; font-weight:600;">${d.label || d.relation_type || 'RELATES_TO'}</td>
                            <td style="color:var(--text-high); font-weight:600;">${d.target}</td>
                            <td><span class="badge" style="color:${color}; border:1px solid ${color};">${d.status}</span></td>
                            <td style="color:var(--text-muted);">${Math.round((d.confidence || 0.5) * 100)}%</td>
                          </tr>
                        `;
                      })
                      .join('')}
                  </tbody>
                </table>
              `
              }
            </div>
          </div>
        `;

      case 'notes':
        return `
          <div class="card font-mono">
            <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
              <span class="card-title">Append-Only Analyst Notes</span>
              <span class="badge badge-verified">IMMUTABLE AUDIT TRAIL</span>
            </div>

            <!-- Notes List -->
            <div style="display:flex; flex-direction:column; gap:10px; margin:12px 0;">
              ${
                controller.notes.length === 0
                  ? `<div style="text-align:center; color:var(--text-muted); padding:16px;">No analyst notes recorded yet. Add initial observations below.</div>`
                  : controller.notes
                      .map(
                        (n) => `
                    <div class="card" style="background:var(--bg-card-alt, #0F172A); padding:10px; border:1px solid var(--border-color);">
                      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; font-size:11px;">
                        <div>
                          <strong style="color:var(--accent-cyan);">${n.author || 'Analyst'}</strong>
                          <span class="badge badge-neutral" style="margin-left:6px;">v${n.version || 1} ${n.version > 1 ? 'AMENDMENT' : 'ORIGINAL'}</span>
                          ${n.parent_note_id ? `<span style="color:var(--text-muted); margin-left:6px;">→ ref: ${n.parent_note_id.slice(0, 8)}</span>` : ''}
                        </div>
                        <div style="color:var(--text-muted);">${n.created_at || ''}</div>
                      </div>
                      <div class="note-body" style="font-size:12px; color:var(--text-high); line-height:1.4;">
                        ${renderSafeMarkdown(n.content)}
                      </div>
                      <div style="margin-top:6px; display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:10px; color:var(--text-muted);">HASH: ${n.content_hash ? n.content_hash.slice(0, 16) + '...' : ''}</span>
                        <button class="btn btn-secondary btn-amend-note" data-note-id="${n.id}" style="font-size:10px; padding:2px 6px;">Amend</button>
                      </div>
                    </div>
                  `
                      )
                      .join('')
              }
            </div>

            <!-- Append Form -->
            <div style="display:flex; flex-direction:column; gap:8px; border-top:1px solid var(--border-color); padding-top:12px;">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <label style="font-size:11px; color:var(--text-muted);" id="note-mode-label">
                  ${controller.activeParentNoteId ? `AMENDING NOTE ${controller.activeParentNoteId.slice(0, 8)} (v2+)` : 'NEW OBSERVATION / HYPOTHESIS'}
                </label>
                <span id="note-char-counter" style="font-size:11px; color:var(--text-muted);">0 / 5,000 chars</span>
              </div>
              <textarea id="note-content-input" class="input-control" rows="4" placeholder="Enter append-only analyst observation or amendment..." maxlength="5000"></textarea>
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <div style="display:flex; gap:6px; align-items:center;">
                  <span style="font-size:11px; color:var(--text-muted);">Author:</span>
                  <input type="text" id="note-author-input" class="input-control font-mono" value="Analyst" style="width:120px; font-size:11px;" />
                  ${
                    controller.activeParentNoteId
                      ? `<button id="btn-cancel-amend" class="btn btn-secondary" style="font-size:10px; padding:2px 6px;">Cancel Amend</button>`
                      : ''
                  }
                </div>
                <button id="btn-append-note" class="btn btn-primary" style="font-size:11px;">Append Note</button>
              </div>
            </div>
          </div>
        `;

      case 'runs':
        return `
          <div class="card font-mono">
            <div class="card-header">
              <span class="card-title">Multi-Agent Investigation Runs</span>
            </div>
            <div style="display:flex; flex-direction:column; gap:8px; margin-top:8px;">
              ${
                controller.runs.length === 0
                  ? `<div style="text-align:center; color:var(--text-muted); padding:20px;">No agent investigations launched on this case yet.</div>`
                  : controller.runs
                      .map(
                        (r) => `
                    <div class="card" style="background:var(--bg-card-alt, #0F172A); padding:10px;">
                      <div style="display:flex; justify-content:space-between; align-items:center; font-size:11px;">
                        <div>
                          <span class="badge badge-primary">${r.agent_name}</span>
                          <span class="badge badge-${r.status === 'COMPLETED' ? 'verified' : r.status === 'RUNNING' ? 'info' : 'critical'}" style="margin-left:6px;">${r.status}</span>
                        </div>
                        <div style="color:var(--text-muted);">${r.started_at || ''} (${r.execution_time_ms || 0}ms)</div>
                      </div>
                      <div style="font-size:12px; color:var(--text-high); margin-top:6px;">
                        ${r.output_summary || 'Task running or completed without summary.'}
                      </div>
                    </div>
                  `
                      )
                      .join('')
              }
            </div>
          </div>
        `;

      case 'custody':
        return `
          <div class="card font-mono">
            <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
              <span class="card-title">Cryptographic Chain of Custody</span>
              <span class="badge badge-verified">TAMPER-EVIDENT AUDIT LEDGER</span>
            </div>
            <div style="overflow-x:auto; margin-top:8px;">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>TIMESTAMP (UTC)</th>
                    <th>ACTOR</th>
                    <th>ACTION</th>
                    <th>ENTITY</th>
                    <th>TARGET SHA-256</th>
                    <th>ORIGIN IP</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  ${
                    controller.custody.length === 0
                      ? `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">No custody events recorded for this case.</td></tr>`
                      : controller.custody
                          .map((ev) => {
                            const pill = formatSha256Pill(ev.target_hash);
                            return `
                        <tr>
                          <td style="color:var(--text-muted);">${ev.timestamp}</td>
                          <td style="color:var(--accent-cyan); font-weight:600;">${ev.actor}</td>
                          <td><span class="badge badge-info">${ev.action}</span></td>
                          <td style="color:var(--text-high);">${ev.entity_type}:${(ev.entity_id || '').slice(0, 8)}</td>
                          <td>
                            <button class="hash-pill" data-full-hash="${pill.full}" title="Click to copy hash">
                              📋 ${pill.short}
                            </button>
                          </td>
                          <td style="color:var(--text-muted);">${ev.ip_address}</td>
                          <td><span class="badge badge-verified">${ev.status || 'SUCCESS'}</span></td>
                        </tr>
                      `;
                          })
                          .join('')
                  }
                </tbody>
              </table>
            </div>
          </div>
        `;

      default:
        return '';
    }
  }

  function bindEvents() {
    wrapper.querySelectorAll('.workspace-tab').forEach((tabBtn) => {
      tabBtn.addEventListener('click', () => {
        const tabId = tabBtn.getAttribute('data-tab');
        controller.switchTab(tabId);
      });
    });

    wrapper.querySelectorAll('.hash-pill').forEach((pill) => {
      pill.addEventListener('click', async () => {
        const fullHash = pill.getAttribute('data-full-hash');
        const copied = await controller.copyHashToClipboard(fullHash);
        const originalText = pill.innerHTML;
        pill.innerHTML = copied ? '✓ COPIED!' : 'FAIL';
        setTimeout(() => {
          pill.innerHTML = originalText;
        }, 1200);
      });
    });

    wrapper.querySelectorAll('.btn-view-raw').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const item = controller.evidence.find((x) => x.id === id);
        if (item) showRawViewer(item);
      });
    });

    // Notes Tab interactions
    const noteInput = wrapper.querySelector('#note-content-input');
    const charCounter = wrapper.querySelector('#note-char-counter');
    if (noteInput && charCounter) {
      noteInput.addEventListener('input', () => {
        charCounter.textContent = `${noteInput.value.length} / 5,000 chars`;
      });
    }

    wrapper.querySelectorAll('.btn-amend-note').forEach((btn) => {
      btn.addEventListener('click', () => {
        const parentId = btn.getAttribute('data-note-id');
        controller.activeParentNoteId = parentId;
        controller.onStateChange();
      });
    });

    wrapper.querySelector('#btn-cancel-amend')?.addEventListener('click', () => {
      controller.activeParentNoteId = null;
      controller.onStateChange();
    });

    wrapper.querySelector('#btn-append-note')?.addEventListener('click', async () => {
      const content = noteInput?.value;
      const author = wrapper.querySelector('#note-author-input')?.value || 'Analyst';
      if (!content || !content.trim()) {
        alert('Note content cannot be empty.');
        return;
      }
      const ok = await controller.appendNote(content, author, controller.activeParentNoteId);
      if (!ok) {
        alert('Failed to append note (exceeded 5,000 chars or server rejected).');
      }
    });
  }

  function showRawViewer(item) {
    const modalContainer = wrapper.querySelector('#raw-modal-container');
    if (!modalContainer) return;

    modalContainer.innerHTML = `
      <div class="modal-overlay">
        <div class="modal-dialog font-mono" style="max-width:650px;">
          <div class="modal-header">
            <span style="font-size:12px; font-weight:700; color:var(--accent-cyan);">[RAW EVIDENCE RECORD: ${item.id}]</span>
            <button id="close-raw-btn" style="background:transparent; border:none; color:var(--text-muted); cursor:pointer;">✕</button>
          </div>
          <div class="modal-body">
            <div style="font-size:11px; margin-bottom:8px; color:var(--text-muted);">FINGERPRINT: <span style="color:var(--accent-cyan);">${item.fingerprintFull}</span></div>
            <pre style="background:var(--bg-input, #0A0D14); padding:10px; border-radius:2px; font-size:11px; max-height:300px; overflow-y:auto; color:var(--text-high); white-space:pre-wrap;">${escapeHtml(item.rawContent || JSON.stringify(item, null, 2))}</pre>
          </div>
          <div class="modal-footer">
            <button id="dismiss-raw-btn" class="btn btn-secondary">Close</button>
          </div>
        </div>
      </div>
    `;

    function escapeHtml(str) {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    }

    modalContainer.querySelector('#close-raw-btn')?.addEventListener('click', () => {
      modalContainer.innerHTML = '';
    });
    modalContainer.querySelector('#dismiss-raw-btn')?.addEventListener('click', () => {
      modalContainer.innerHTML = '';
    });
  }

  controller.onStateChange = () => render();
  containerEl.appendChild(wrapper);
  controller.load();
  render();

  return controller;
}
