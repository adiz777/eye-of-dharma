// public/js/views/data_sources.js
// EYE OF DHARMA (EOD) — OSINT Data Sources & Connector Telemetry View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[SRCS]</span> Data Sources</h1>
        <div class="view-subtitle font-mono">OSINT CONNECTOR TELEMETRY, TOKEN BUCKET RATE LIMITS & HEALTH BOARD</div>
      </div>
      <div class="view-actions">
        <button class="btn btn-primary" id="btn-sync-all-sources" style="font-size:11px;">
          🔄 Trigger Full Connector Ingestion
        </button>
      </div>
    </div>

    <!-- Connector Health Cards -->
    <div class="card-grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
      <!-- USGS -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">USGS Earthquakes GeoJSON</span>
          <span class="badge badge-verified">NOMINAL</span>
        </div>
        <div style="font-size:11px; color:var(--text-muted); display:flex; flex-direction:column; gap:4px;">
          <div>ENDPOINT: <code>earthquake.usgs.gov/earthquakes/feed/v1.0</code></div>
          <div>LATENCY: <strong style="color:var(--status-verified);">142ms</strong> | REFILL: <strong>1.0 tok/s</strong></div>
          <div>FRESHNESS: <strong>4m ago</strong> | ERRORS: <strong>0</strong></div>
        </div>
      </div>

      <!-- NASA EONET -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">NASA EONET v3 Natural Hazards</span>
          <span class="badge badge-verified">NOMINAL</span>
        </div>
        <div style="font-size:11px; color:var(--text-muted); display:flex; flex-direction:column; gap:4px;">
          <div>ENDPOINT: <code>eonet.gsfc.nasa.gov/api/v3/events</code></div>
          <div>LATENCY: <strong style="color:var(--status-verified);">218ms</strong> | REFILL: <strong>0.5 tok/s</strong></div>
          <div>FRESHNESS: <strong>12m ago</strong> | ERRORS: <strong>0</strong></div>
        </div>
      </div>

      <!-- CISA KEV -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">CISA Known Exploited Vulnerabilities</span>
          <span class="badge badge-verified">NOMINAL</span>
        </div>
        <div style="font-size:11px; color:var(--text-muted); display:flex; flex-direction:column; gap:4px;">
          <div>ENDPOINT: <code>cisa.gov/sites/default/files/.../known_exploited_vulnerabilities.json</code></div>
          <div>LATENCY: <strong style="color:var(--status-verified);">185ms</strong> | REFILL: <strong>0.2 tok/s</strong></div>
          <div>FRESHNESS: <strong>1h ago</strong> | ERRORS: <strong>0</strong></div>
        </div>
      </div>

      <!-- CISA Advisories RSS -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">CISA Cybersecurity Advisories (RSS)</span>
          <span class="badge badge-verified">NOMINAL</span>
        </div>
        <div style="font-size:11px; color:var(--text-muted); display:flex; flex-direction:column; gap:4px;">
          <div>ENDPOINT: <code>cisa.gov/cybersecurity-advisories/all.xml</code></div>
          <div>LATENCY: <strong style="color:var(--status-verified);">164ms</strong> | REFILL: <strong>0.5 tok/s</strong></div>
          <div>FRESHNESS: <strong>22m ago</strong> | ERRORS: <strong>0</strong></div>
        </div>
      </div>

      <!-- crt.sh -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">crt.sh Certificate Transparency</span>
          <span class="badge badge-inferred">RATE-LIMITED</span>
        </div>
        <div style="font-size:11px; color:var(--text-muted); display:flex; flex-direction:column; gap:4px;">
          <div>ENDPOINT: <code>crt.sh/?q=...&output=json</code></div>
          <div>LATENCY: <strong style="color:var(--status-inferred);">840ms</strong> | BACKOFF: <strong>Exponential Jitter</strong></div>
          <div>FRESHNESS: <strong>On-Demand</strong> | TIMEOUT: <strong>10000ms</strong></div>
        </div>
      </div>

      <!-- DNS & RDAP -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">DNS-over-HTTPS & RDAP Registries</span>
          <span class="badge badge-verified">NOMINAL</span>
        </div>
        <div style="font-size:11px; color:var(--text-muted); display:flex; flex-direction:column; gap:4px;">
          <div>RESOLVERS: <code>1.1.1.1, 8.8.8.8, ICANN RDAP</code></div>
          <div>LATENCY: <strong style="color:var(--status-verified);">38ms</strong> | PINNING: <strong>Active DNS Rebinding Defense</strong></div>
          <div>SSRF FIREWALL: <strong>6-Stage CIDR Filter Enabled</strong></div>
        </div>
      </div>
    </div>
  `;

  container.querySelector('#btn-sync-all-sources')?.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/v1/feeds/refresh', { method: 'POST' });
      const data = await res.json();
      alert(`[✓] Connector ingestion triggered: ${data.items_ingested || 0} items updated.`);
    } catch {
      alert('Failed to trigger connector sync.');
    }
  });
}
