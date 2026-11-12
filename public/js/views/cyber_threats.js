// public/js/views/cyber_threats.js
// EYE OF DHARMA (EOD) — Cyber Threats & KEV Matrix View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[CYBER]</span> Cyber Threats</h1>
        <div class="view-subtitle font-mono">CISA KNOWN EXPLOITED VULNERABILITIES (KEV) & THREAT ACTOR MATRIX</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-critical font-mono">KEV CATALOG ACTIVE</span>
      </div>
    </div>

    <!-- Threat KPI Summary Cards -->
    <div class="card-grid">
      <div class="card">
        <div class="card-header"><span class="card-title">CISA KEV Catalog</span></div>
        <div class="card-metric font-mono" style="color:var(--accent-cyan);">1,284</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Actively exploited vulnerabilities tracked</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Ransomware Campaign Tied</span></div>
        <div class="card-metric font-mono" style="color:var(--status-critical);">38%</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Exploited within 48h of public disclosure</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Zero-Day Exposure</span></div>
        <div class="card-metric font-mono" style="color:var(--status-inferred);">12</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Unpatched perimeter exposure flags</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Tracked Threat Actors</span></div>
        <div class="card-metric font-mono" style="color:var(--accent-gold);">APT-44</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Sandworm / FrostyDragon Nexus</div>
      </div>
    </div>

    <!-- Active IOC Table -->
    <div class="card font-mono" style="margin-top:16px;">
      <div class="card-header">
        <span class="card-title">Corroborated Threat Indicators (IOCs)</span>
        <span class="text-muted" style="font-size:11px;" id="threats-count-hud">LOADING...</span>
      </div>
      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>INDICATOR TYPE</th>
              <th>VALUE / PATTERN</th>
              <th>SEVERITY</th>
              <th>CONFIDENCE</th>
              <th>THREAT ACTOR</th>
              <th>FIRST SEEN</th>
            </tr>
          </thead>
          <tbody id="threats-tbody">
            <tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">Querying CTI repository...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  fetch('/api/v1/threats')
    .then((r) => r.json())
    .then((data) => {
      const tbody = container.querySelector('#threats-tbody');
      const hud = container.querySelector('#threats-count-hud');
      if (!tbody) return;

      const items = data.items || data.threats || [];
      if (hud) hud.textContent = `${items.length} ACTIVE INDICATORS`;

      if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">No threat indicators registered in active CTI database.</td></tr>`;
        return;
      }

      tbody.innerHTML = items
        .map(
          (t) => `
        <tr>
          <td><span class="badge badge-info">${t.indicator_type}</span></td>
          <td style="color:var(--accent-cyan); font-weight:600;">${t.value}</td>
          <td><span class="badge ${t.severity === 'CRITICAL' ? 'badge-critical' : 'badge-inferred'}">${t.severity}</span></td>
          <td style="color:var(--text-muted);">${Math.round((t.confidence || 0.9) * 100)}%</td>
          <td style="color:var(--text-high);">${t.threat_actor || 'UNKNOWN'}</td>
          <td style="color:var(--text-muted);">${t.created_at ? t.created_at.substring(0, 10) : '2026-10-28'}</td>
        </tr>
      `
        )
        .join('');
    })
    .catch((err) => {
      console.warn('[CyberThreats] Failed to load threats:', err);
    });
}
