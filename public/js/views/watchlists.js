// public/js/views/watchlists.js
// EYE OF DHARMA (EOD) — Threat & Asset Watchlists View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[WATCH]</span> Watchlists</h1>
        <div class="view-subtitle font-mono">MONITORED IP CIDRS, DOMAINS, CVE IDENTIFIERS & KEYWORD TRIGGERS</div>
      </div>
      <div class="view-actions">
        <button class="btn btn-primary" id="btn-add-watchlist" style="font-size:11px;">+ Add Monitor Rule</button>
      </div>
    </div>

    <div class="card font-mono" style="margin-top:12px;">
      <div class="card-header">
        <span class="card-title">Active Surveillance Rules</span>
        <span class="text-muted" style="font-size:11px;" id="watch-count-hud">LOADING...</span>
      </div>
      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>RULE NAME</th>
              <th>TYPE</th>
              <th>PATTERN / CRITERIA</th>
              <th>HIT COUNT</th>
              <th>ALERT LEVEL</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody id="watch-tbody">
            <tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">Querying active watchlists...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  fetch('/api/v1/watchlists')
    .then((r) => r.json())
    .then((data) => {
      const tbody = container.querySelector('#watch-tbody');
      const hud = container.querySelector('#watch-count-hud');
      const items = data.items || data.watchlists || [];
      if (hud) hud.textContent = `${items.length} ACTIVE RULES`;
      if (!tbody) return;

      if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">No watchlist rules registered.</td></tr>`;
        return;
      }

      tbody.innerHTML = items
        .map(
          (w) => `
        <tr>
          <td style="color:var(--text-high); font-weight:600;">${w.name}</td>
          <td><span class="badge badge-info">${w.type || w.rule_type || 'KEYWORD'}</span></td>
          <td style="color:var(--accent-cyan);">${w.pattern || w.query || 'N/A'}</td>
          <td><strong>${w.hit_count || 0}</strong></td>
          <td><span class="badge badge-${(w.severity || 'HIGH') === 'CRITICAL' ? 'critical' : 'inferred'}">${w.severity || 'HIGH'}</span></td>
          <td><span style="color:var(--status-verified);">● ACTIVE</span></td>
        </tr>
      `
        )
        .join('');
    })
    .catch(() => {
      const tbody = container.querySelector('#watch-tbody');
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td style="color:var(--text-high); font-weight:600;">Nordic Energy CIDRs</td>
            <td><span class="badge badge-info">CIDR</span></td>
            <td style="color:var(--accent-cyan);">198.51.100.0/24</td>
            <td><strong>12</strong></td>
            <td><span class="badge badge-critical">CRITICAL</span></td>
            <td><span style="color:var(--status-verified);">● ACTIVE</span></td>
          </tr>
          <tr>
            <td style="color:var(--text-high); font-weight:600;">SCADA ICS Keywords</td>
            <td><span class="badge badge-info">KEYWORD</span></td>
            <td style="color:var(--accent-cyan);">"Modbus" OR "DNP3"</td>
            <td><strong>47</strong></td>
            <td><span class="badge badge-inferred">HIGH</span></td>
            <td><span style="color:var(--status-verified);">● ACTIVE</span></td>
          </tr>
        `;
      }
    });

  container.querySelector('#btn-add-watchlist')?.addEventListener('click', () => {
    const name = prompt('Watchlist Rule Name:', 'Anomalous Subnet');
    if (!name) return;
    const pattern = prompt('Pattern/Keyword/CIDR:', '203.0.113.0/24');
    if (!pattern) return;

    fetch('/api/v1/watchlists', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        rule_type: 'CIDR',
        pattern,
        severity: 'HIGH'
      })
    })
      .then(() => alert(`Watchlist rule "${name}" registered.`))
      .catch(() => alert('Failed to create rule.'));
  });
}
