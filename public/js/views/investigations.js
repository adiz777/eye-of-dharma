// public/js/views/investigations.js
// EYE OF DHARMA (EOD) — Multi-Agent Intelligence Investigation Engine View

import { mountFootprintUI } from '../components/footprint_ui.js';
import { mountEntityLookup } from '../components/entity_lookup_ui.js';

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[INVST]</span> Investigations</h1>
        <div class="view-subtitle font-mono">MULTI-AGENT INTELLIGENCE ORCHESTRATION & INVESTIGATION DAG</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-neutral font-mono">AGENT RUNS: RECORDED ONLY</span>
      </div>
    </div>

    <!-- State Machine Telemetry Bar -->
    <div class="card font-mono" style="padding:12px 16px;">
      <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
        <span style="font-weight:700; color:var(--text-muted); font-size:11px;">EXECUTION STATE MACHINE:</span>
        <div style="display:flex; align-items:center; gap:8px; font-size:11px;">
          <span class="badge badge-neutral">PLANNED</span>
          <span>→</span>
          <span class="badge badge-info">RUNNING</span>
          <span>→</span>
          <span class="badge badge-warning">VERIFYING</span>
          <span>→</span>
          <span class="badge badge-success">COMPLETED</span>
          <span style="color:var(--text-muted); margin-left:6px;">/</span>
          <span class="badge badge-danger">FAILED</span>
        </div>
      </div>
    </div>

    <!-- 7 Agent Personas Grid -->
    <div style="margin-top:16px;">
      <h3 class="font-mono" style="font-size:12px; color:var(--text-muted); text-transform:uppercase; margin-bottom:8px;">
        Active Agent Personas (7 Roles)
      </h3>
      <div class="card-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
        <div class="card font-mono" style="border-left:3px solid var(--accent-cyan);">
          <div style="font-weight:700; color:var(--accent-cyan);">DHARMA</div>
          <div style="font-size:10px; color:var(--text-muted);">COORDINATOR</div>
          <div style="font-size:11px; margin-top:6px;">Task decomposition & investigation DAG dispatch.</div>
        </div>
        <div class="card font-mono" style="border-left:3px solid #10B981;">
          <div style="font-weight:700; color:#10B981;">NETRA</div>
          <div style="font-size:10px; color:var(--text-muted);">RESEARCHER</div>
          <div style="font-size:11px; margin-top:6px;">Public registries and feed ingestion.</div>
        </div>
        <div class="card font-mono" style="border-left:3px solid #38BDF8;">
          <div style="font-weight:700; color:#38BDF8;">CIPHER</div>
          <div style="font-size:10px; color:var(--text-muted);">NETWORK & INFRA</div>
          <div style="font-size:11px; margin-top:6px;">DNS, RDAP, BGP routing & SSL/TLS certificates.</div>
        </div>
        <div class="card font-mono" style="border-left:3px solid #EF4444;">
          <div style="font-weight:700; color:#EF4444;">SENTINEL</div>
          <div style="font-size:10px; color:var(--text-muted);">THREAT INTEL</div>
          <div style="font-size:11px; margin-top:6px;">CISA KEV, CVEs, ransomware & threat actor attribution.</div>
        </div>
        <div class="card font-mono" style="border-left:3px solid #F59E0B;">
          <div style="font-weight:700; color:#F59E0B;">ATLAS</div>
          <div style="font-size:10px; color:var(--text-muted);">GEOSPATIAL</div>
          <div style="font-size:11px; margin-top:6px;">USGS earthquakes, NASA EONET & SCADA facilities.</div>
        </div>
        <div class="card font-mono" style="border-left:3px solid #D4AF37;">
          <div style="font-weight:700; color:#D4AF37;">VERITAS</div>
          <div style="font-size:10px; color:var(--text-muted);">VERIFICATION</div>
          <div style="font-size:11px; margin-top:6px;">Anti-hallucination citation & contradiction detection.</div>
        </div>
        <div class="card font-mono" style="border-left:3px solid #A855F7;">
          <div style="font-weight:700; color:#A855F7;">SCRIBE</div>
          <div style="font-size:10px; color:var(--text-muted);">REPORTING</div>
          <div style="font-size:11px; margin-top:6px;">Grounded dossier compilation & multi-format export.</div>
        </div>
      </div>
    </div>

    <div id="entity-mount-point" style="margin-top:20px;"></div>

    <!-- Embedded Digital Footprint Recon Section -->
    <div style="margin-top:20px;">
      <h3 class="font-mono" style="font-size:12px; color:var(--text-muted); text-transform:uppercase; margin-bottom:8px;">
        Digital Footprint Investigation Engine
      </h3>
      <div id="footprint-mount-point"></div>
    </div>
  `;

  mountEntityLookup(container.querySelector('#entity-mount-point'));

  // Mount Footprint Recon UI
  const fpMount = container.querySelector('#footprint-mount-point');
  if (fpMount) {
    mountFootprintUI(fpMount);
  }
}
