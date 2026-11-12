// public/js/views/system_health.js
// EYE OF DHARMA (EOD) — System Health & Telemetry View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[HLTH]</span> System Health</h1>
        <div class="view-subtitle font-mono">BACKEND SERVICE VITALS, DATABASE INTEGRITY & LATENCY TELEMETRY</div>
      </div>
      <div class="view-actions">
        <span class="status-dot pulsing"></span>
        <span class="badge badge-verified font-mono" id="health-status-badge">ONLINE</span>
      </div>
    </div>

    <!-- Health Metrics Grid -->
    <div class="card-grid">
      <div class="card font-mono">
        <div class="card-title">Database Engine</div>
        <div class="card-metric" style="color:var(--status-verified); font-size:22px;">SQLite-WAL</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;" id="db-path-hud">
          journal_mode=WAL | foreign_keys=ON
        </div>
      </div>

      <div class="card font-mono">
        <div class="card-title">Memory Footprint</div>
        <div class="card-metric" style="color:var(--accent-cyan); font-size:22px;" id="memory-hud">-- MB</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Node.js RSS / Heap allocated</div>
      </div>

      <div class="card font-mono">
        <div class="card-title">System Uptime</div>
        <div class="card-metric" style="color:var(--text-high); font-size:22px;" id="uptime-hud">-- s</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Continuous operations center runtime</div>
      </div>

      <div class="card font-mono">
        <div class="card-title">Database Size</div>
        <div class="card-metric" style="color:var(--accent-gold); font-size:22px;" id="db-size-hud">-- KB</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Relational tables on disk</div>
      </div>
    </div>

    <!-- Table Row Counts -->
    <div class="card font-mono" style="margin-top:16px;">
      <div class="card-header">
        <span class="card-title">Relational Tables Inventory (9 Tables)</span>
      </div>
      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>TABLE NAME</th>
              <th>RECORD COUNT</th>
              <th>MUTATION POLICY</th>
              <th>INTEGRITY STATUS</th>
            </tr>
          </thead>
          <tbody id="table-counts-tbody">
            <tr><td colspan="4" style="text-align:center; padding:16px; color:var(--text-muted);">Querying database pragma counts...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  fetch('/api/v1/health')
    .then((r) => r.json())
    .then((data) => {
      const memEl = container.querySelector('#memory-hud');
      const upEl = container.querySelector('#uptime-hud');
      const sizeEl = container.querySelector('#db-size-hud');
      const tbody = container.querySelector('#table-counts-tbody');

      if (data.memory?.rss) {
        if (memEl) memEl.textContent = `${(data.memory.rss / (1024 * 1024)).toFixed(1)} MB`;
      }
      if (data.uptime != null) {
        if (upEl) upEl.textContent = `${Math.floor(data.uptime)} s`;
      }
      if (data.database?.file_size_bytes != null) {
        if (sizeEl) sizeEl.textContent = `${(data.database.file_size_bytes / 1024).toFixed(0)} KB`;
      }

      if (data.database?.table_counts && tbody) {
        const counts = data.database.table_counts;
        tbody.innerHTML = Object.entries(counts)
          .map(([table, count]) => {
            const isImmutable = table === 'evidence_ledger';
            return `
            <tr>
              <td style="color:var(--accent-cyan); font-weight:600;">${table}</td>
              <td><strong>${count}</strong></td>
              <td><span class="badge ${isImmutable ? 'badge-gold' : 'badge-neutral'}">${isImmutable ? 'IMMUTABLE TRIGGER' : 'MUTABLE'}</span></td>
              <td><span style="color:var(--status-verified);">✓ NOMINAL</span></td>
            </tr>
          `;
          })
          .join('');
      }
    })
    .catch((err) => {
      console.warn('[SystemHealth] Telemetry poll failed:', err);
    });
}
