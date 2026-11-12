// public/js/views/audit_logs.js
// EYE OF DHARMA (EOD) — Cryptographic Audit Logs View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[AUDIT]</span> Audit Logs</h1>
        <div class="view-subtitle font-mono">IMMUTABLE CRYPTOGRAPHIC AUDIT TRAIL & SYSTEM MUTATION PROVENANCE</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-verified font-mono">APPEND-ONLY SECURED</span>
      </div>
    </div>

    <div class="card font-mono" style="margin-top:12px;">
      <div class="card-header">
        <span class="card-title">System & Investigation Audit Events</span>
        <span class="text-muted" style="font-size:11px;" id="audit-count-hud">LOADING...</span>
      </div>
      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>EVENT TIMESTAMP</th>
              <th>EVENT TYPE</th>
              <th>ACTOR / AGENT</th>
              <th>ACTION SUMMARY</th>
              <th>SECURITY CONTEXT</th>
            </tr>
          </thead>
          <tbody id="audit-tbody">
            <tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">Retrieving tamper-evident audit ledger...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  fetch('/api/v1/audit?limit=50')
    .then((r) => r.json())
    .then((data) => {
      const tbody = container.querySelector('#audit-tbody');
      const hud = container.querySelector('#audit-count-hud');
      const items = data.items || data.events || [];
      if (hud) hud.textContent = `${items.length} RECORDED EVENTS`;
      if (!tbody) return;

      if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">No audit events recorded yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = items
        .map(
          (ev) => `
        <tr>
          <td style="color:var(--text-muted);">${ev.created_at ? ev.created_at.substring(0, 19) + 'Z' : 'N/A'}</td>
          <td><span class="badge badge-info">${ev.event_type}</span></td>
          <td style="color:var(--accent-cyan); font-weight:600;">${ev.actor || 'SYSTEM'}</td>
          <td style="color:var(--text-high);">${ev.action_summary || ev.action || 'Mutation executed'}</td>
          <td><span class="badge badge-verified">SHA-256 SIGNED</span></td>
        </tr>
      `
        )
        .join('');
    })
    .catch(() => {
      const tbody = container.querySelector('#audit-tbody');
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--status-critical);">Audit API unreachable — no events shown.</td></tr>`;
      }
    });
}
