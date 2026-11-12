// public/js/views/global_monitor.js
// EYE OF DHARMA (EOD) — Global Monitor Geospatial View

import { MapView } from '../components/map_view.js';

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[MAP]</span> Global Monitor</h1>
        <div class="view-subtitle font-mono">GEOSPATIAL INTELLIGENCE & TACTICAL MAP DECK</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-info font-mono" id="map-telemetry-hud">HAZARDS: -- | CYBER: -- | NEWS: -- | INFRA: --</span>
      </div>
    </div>

    <div class="map-view-shell">
      <!-- Top Map Layer Toggles -->
      <div class="map-toolbar font-mono">
        <div class="map-layer-toggles">
          <span style="color:var(--text-muted); font-size:10px; margin-right:6px;">ACTIVE LAYERS:</span>
          <label class="map-layer-toggle" style="color:#EF4444;">
            <input type="checkbox" id="layer-hazards" checked />
            <span>Hazards (USGS/EONET)</span>
          </label>
          <label class="map-layer-toggle" style="color:#00E5FF;">
            <input type="checkbox" id="layer-cyber" checked />
            <span>Cyber (CISA)</span>
          </label>
          <label class="map-layer-toggle" style="color:#10B981;">
            <input type="checkbox" id="layer-news" checked />
            <span>News (RSS)</span>
          </label>
          <label class="map-layer-toggle" style="color:#D4AF37; opacity:0.5;" title="No public infrastructure source configured yet">
            <input type="checkbox" id="layer-infra" disabled />
            <span>Infrastructure (no source)</span>
          </label>
        </div>
        <div>
          <button class="btn btn-secondary" id="map-sync-btn" style="padding:4px 8px; font-size:10px;">
            SYNC LIVE FEEDS
          </button>
        </div>
      </div>

      <!-- Map Canvas Container -->
      <div id="map-canvas-container" class="map-canvas-container"></div>
    </div>
  `;

  const mapView = new MapView('map-canvas-container');
  mapView.init();

  // Wire layer checkboxes
  container.querySelector('#layer-hazards')?.addEventListener('change', (e) => {
    mapView.toggleLayer('hazards', e.target.checked);
  });
  container.querySelector('#layer-cyber')?.addEventListener('change', (e) => {
    mapView.toggleLayer('cyber', e.target.checked);
  });
  container.querySelector('#layer-news')?.addEventListener('change', (e) => {
    mapView.toggleLayer('news', e.target.checked);
  });
  container.querySelector('#layer-infra')?.addEventListener('change', (e) => {
    mapView.toggleLayer('infrastructure', e.target.checked);
  });

  container.querySelector('#map-sync-btn')?.addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'SYNCING…';
    try {
      await fetch('/api/v1/feeds/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    } finally {
      await mapView.refreshData();
      btn.disabled = false;
      btn.textContent = 'SYNC LIVE FEEDS';
    }
  });
}
