// public/js/components/map_view.js
// EYE OF DHARMA (EOD) — MapLibre GL Geospatial Map Component with 4 Toggleable Layers & Supercluster

export class MapView {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.options = options;
    this.map = null;
    this.layersVisible = {
      hazards: true,
      cyber: true,
      news: true,
      infrastructure: true
    };
    this.dataSources = {
      hazards: { type: 'FeatureCollection', features: [] },
      cyber: { type: 'FeatureCollection', features: [] },
      news: { type: 'FeatureCollection', features: [] },
      infrastructure: { type: 'FeatureCollection', features: [] }
    };
    this.activeCaseId = options.activeCaseId || 'case-00000000-0000-0000-0000-000000000001';
  }

  /**
   * Initializes the MapLibre GL instance or renders tactical fallback
   */
  async init() {
    if (typeof document === 'undefined') return;
    const container = document.getElementById(this.containerId);
    if (!container) return;

    if (typeof window === 'undefined' || typeof window.maplibregl === 'undefined') {
      this.renderFallback(container);
      return;
    }

    try {
      this.map = new window.maplibregl.Map({
        container: this.containerId,
        // OpenFreeMap: free, keyless OSM vector tiles (attribution shown by the style).
        style: 'https://tiles.openfreemap.org/styles/dark',
        center: [0, 20], // Global view
        zoom: 1.6,
        pitch: 0,
        bearing: 0,
        attributionControl: true
      });

      this.map.addControl(new window.maplibregl.NavigationControl({ showCompass: true }), 'top-left');

      this.map.on('load', async () => {
        this.initLayers();
        await this.refreshData();
        this.setupEventHandlers();
      });

      const canvas = this.map.getCanvas();
      canvas?.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        console.warn('[MapView] WebGL context lost. Tactical recovery in progress.');
      });
      canvas?.addEventListener('webglcontextrestored', () => {
        this.map.setStyle('https://tiles.openfreemap.org/styles/dark');
      });
    } catch (err) {
      console.warn('[MapView] WebGL initialization failed, falling back:', err);
      this.renderFallback(container);
    }
  }

  /**
   * Configures GeoJSON sources and clustering
   */
  initLayers() {
    if (!this.map) return;

    // 1. Natural Hazards Source (USGS + EONET) with Supercluster
    this.map.addSource('hazards-source', {
      type: 'geojson',
      data: this.dataSources.hazards,
      cluster: true,
      clusterMaxZoom: 14,
      clusterRadius: 50
    });

    // Hazards Cluster Circle Layer
    this.map.addLayer({
      id: 'hazards-clusters',
      type: 'circle',
      source: 'hazards-source',
      filter: ['has', 'point_count'],
      paint: {
        'circle-color': ['step', ['get', 'point_count'], '#0F172A', 10, '#162036', 50, '#1E293B'],
        'circle-stroke-color': ['step', ['get', 'point_count'], '#00E5FF', 10, '#FFA726', 50, '#EF4444'],
        'circle-stroke-width': 2,
        'circle-radius': ['step', ['get', 'point_count'], 18, 10, 24, 50, 30]
      }
    });

    // Hazards Cluster Count Badge
    this.map.addLayer({
      id: 'hazards-cluster-count',
      type: 'symbol',
      source: 'hazards-source',
      filter: ['has', 'point_count'],
      layout: {
        'text-field': '{point_count_abbreviated}',
        'text-font': ['Noto Sans Regular'],
        'text-size': 12
      },
      paint: { 'text-color': '#F8FAFC' }
    });

    // Hazards Unclustered Points (Scaled by Magnitude)
    this.map.addLayer({
      id: 'hazards-points',
      type: 'circle',
      source: 'hazards-source',
      filter: ['!', ['has', 'point_count']],
      paint: {
        'circle-radius': [
          'interpolate', ['linear'], ['coalesce', ['get', 'mag'], 2.5],
          1, 4,
          3, 7,
          5, 14,
          7, 24,
          9, 36
        ],
        'circle-color': [
          'step', ['coalesce', ['get', 'mag'], 2.5],
          '#38BDF8', // M < 3.0: Sky blue
          3.0, '#F59E0B', // M 3.0 - 5.0: Amber
          5.0, '#EF4444'  // M >= 5.0: Crimson
        ],
        'circle-opacity': 0.85,
        'circle-stroke-width': 1.5,
        'circle-stroke-color': '#0A0D14'
      }
    });

    // 2. Cyber Threats Layer
    this.map.addSource('cyber-source', {
      type: 'geojson',
      data: this.dataSources.cyber
    });

    this.map.addLayer({
      id: 'cyber-halo',
      type: 'circle',
      source: 'cyber-source',
      paint: {
        'circle-radius': 12,
        'circle-color': '#00E5FF',
        'circle-opacity': 0.35,
        'circle-blur': 0.4
      }
    });

    this.map.addLayer({
      id: 'cyber-points',
      type: 'circle',
      source: 'cyber-source',
      paint: {
        'circle-radius': 5,
        'circle-color': '#00E5FF',
        'circle-stroke-width': 1.5,
        'circle-stroke-color': '#F8FAFC'
      }
    });

    // 3. News Layer
    this.map.addSource('news-source', {
      type: 'geojson',
      data: this.dataSources.news
    });

    this.map.addLayer({
      id: 'news-points',
      type: 'circle',
      source: 'news-source',
      paint: {
        'circle-radius': 6,
        'circle-color': '#10B981',
        'circle-stroke-width': 1.5,
        'circle-stroke-color': '#0A0D14'
      }
    });

    // 4. Infrastructure Assets Layer
    this.map.addSource('infrastructure-source', {
      type: 'geojson',
      data: this.dataSources.infrastructure
    });

    this.map.addLayer({
      id: 'infrastructure-points',
      type: 'circle',
      source: 'infrastructure-source',
      paint: {
        'circle-radius': 7,
        'circle-color': '#D4AF37',
        'circle-stroke-width': 2,
        'circle-stroke-color': '#0F172A'
      }
    });
  }

  /**
   * Fetches intelligence feeds and converts to GeoJSON
   */
  async refreshData() {
    try {
      // API caps pages at 100, so pull each geolocated category separately.
      const pages = await Promise.all(['EARTHQUAKE', 'HAZARD', 'NEWS'].map((c) => fetch(`/api/v1/feeds?category=${c}&limit=100`).then((r) => r.json())));
      const json = { success: true, items: pages.flatMap((p) => p.items || []) };
      if (!json.success || !Array.isArray(json.items)) return;

      const hazardsFeatures = [];
      const cyberFeatures = [];
      const newsFeatures = [];

      for (const item of json.items) {
        let lat = item.geocoding_lat;
        let lon = item.geocoding_lon;

        // Extract coordinates from payload if not top-level
        if ((lat == null || lon == null) && item.payload) {
          const p = typeof item.payload === 'string' ? JSON.parse(item.payload) : item.payload;
          if (p.geometry?.coordinates) {
            lon = p.geometry.coordinates[0];
            lat = p.geometry.coordinates[1];
          }
        }

        if (lat == null || lon == null) continue;

        const feature = {
          type: 'Feature',
          geometry: { type: 'Point', coordinates: [lon, lat] },
          properties: {
            id: item.id,
            title: item.title,
            category: item.category,
            severity: item.severity,
            source_url: item.source_url,
            published_at: item.published_at,
            summary: item.summary || item.title,
            mag: item.payload?.mag || 2.5
          }
        };

        if (item.category === 'EARTHQUAKE' || item.category === 'HAZARD') {
          hazardsFeatures.push(feature);
        } else if (item.category === 'ADVISORY' || item.category === 'VULNERABILITY') {
          cyberFeatures.push(feature);
        } else {
          newsFeatures.push(feature);
        }
      }

      this.dataSources.hazards.features = hazardsFeatures;
      this.dataSources.cyber.features = cyberFeatures;
      this.dataSources.news.features = newsFeatures;

      // shortcut: no public infrastructure connector yet, layer stays empty until one is added.
      this.dataSources.infrastructure.features = [];

      // Update MapLibre sources if initialized
      if (this.map) {
        if (this.map.getSource('hazards-source')) this.map.getSource('hazards-source').setData(this.dataSources.hazards);
        if (this.map.getSource('cyber-source')) this.map.getSource('cyber-source').setData(this.dataSources.cyber);
        if (this.map.getSource('news-source')) this.map.getSource('news-source').setData(this.dataSources.news);
        if (this.map.getSource('infrastructure-source')) this.map.getSource('infrastructure-source').setData(this.dataSources.infrastructure);
      }

      this.updateHudCounts();
    } catch (err) {
      console.error('[MapView] Failed to refresh map data:', err);
    }
  }

  /**
   * Interactive popups with coordinate HUD readout & "Attach to Active Case"
   */
  setupEventHandlers() {
    if (!this.map) return;
    const clickableLayers = ['hazards-points', 'cyber-points', 'news-points', 'infrastructure-points'];

    for (const layerId of clickableLayers) {
      this.map.on('mouseenter', layerId, () => {
        if (this.map.getCanvas()) this.map.getCanvas().style.cursor = 'pointer';
      });
      this.map.on('mouseleave', layerId, () => {
        if (this.map.getCanvas()) this.map.getCanvas().style.cursor = '';
      });

      this.map.on('click', layerId, (e) => {
        if (!e.features || !e.features[0]) return;
        const f = e.features[0];
        const props = f.properties;
        const coords = f.geometry.coordinates;
        const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        const safeUrl = /^https?:\/\//i.test(props.source_url || '') ? esc(props.source_url) : '';

        const popupContent = `
          <div class="eod-map-popup" style="background:#0F172A; color:#F8FAFC; border:1px solid #1E293B; padding:12px; border-radius:4px; font-family:var(--font-sans); min-width:260px;">
            <div style="font-size:10px; font-weight:700; color:#00E5FF; text-transform:uppercase; margin-bottom:4px;">
              [${esc(props.category || 'INTELLIGENCE')}] ${props.severity ? `• ${esc(props.severity)}` : ''}
            </div>
            <div style="font-size:13px; font-weight:600; line-height:1.3; margin-bottom:6px;">${esc(props.title)}</div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#94A3B8; background:#0A0D14; padding:4px 6px; border-radius:3px; margin-bottom:8px;">
              LAT: ${Number(coords[1]).toFixed(4)}° | LON: ${Number(coords[0]).toFixed(4)}°<br/>
              PUBLISHED: ${esc(props.published_at || 'unknown')}
            </div>
            <div style="font-size:11px; color:#CBD5E1; margin-bottom:10px;">${esc(props.summary || '')}</div>
            ${safeUrl ? `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer" style="display:block; font-size:11px; color:#00E5FF; margin-bottom:8px;">Open original source ↗</a>` : ''}
            <button id="btn-attach-evidence" data-id="${esc(props.id)}" class="btn btn-primary" style="width:100%; font-size:11px;">
              + Attach to Active Case
            </button>
          </div>
        `;

        new window.maplibregl.Popup({ offset: 12, closeButton: true })
          .setLngLat(coords)
          .setHTML(popupContent)
          .addTo(this.map);

        setTimeout(() => {
          const btn = document.getElementById('btn-attach-evidence');
          if (btn) {
            btn.addEventListener('click', () => this.attachToCase(props, coords));
          }
        }, 50);
      });
    }

    // Cluster zoom expansion on click
    this.map.on('click', 'hazards-clusters', (e) => {
      const features = this.map.queryRenderedFeatures(e.point, { layers: ['hazards-clusters'] });
      const clusterId = features[0].properties.cluster_id;
      this.map.getSource('hazards-source').getClusterExpansionZoom(clusterId, (err, zoom) => {
        if (err) return;
        this.map.easeTo({ center: features[0].geometry.coordinates, zoom: zoom + 0.5 });
      });
    });
  }

  /**
   * Attaches clicked geo-record to active case as immutable evidence
   */
  async attachToCase(props, coords) {
    try {
      const payload = {
        source_url: props.source_url || `https://eod.internal/geo/${props.id}`,
        source_type: props.category === 'EARTHQUAKE' ? 'USGS_EARTHQUAKE' : 'RSS_FEED',
        source_title: props.title,
        raw_content: JSON.stringify({ ...props, coordinates: coords }),
        verification_status: 'Observed',
        confidence_score: 0.85,
        notes: `Attached via Global Geospatial Map HUD at [${coords[1]}, ${coords[0]}]`
      };

      const res = await fetch(`/api/v1/cases/${this.activeCaseId}/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        alert(`[✓] Successfully attached "${props.title}" to active case ${this.activeCaseId}`);
      } else {
        alert(`[!] Failed to attach evidence: ${data.error?.message || 'Server rejected request'}`);
      }
    } catch (err) {
      console.error('[MapView] Error attaching to case:', err);
    }
  }

  /**
   * Toggles visibility of an intelligence layer
   */
  toggleLayer(layerKey, isVisible) {
    this.layersVisible[layerKey] = isVisible;
    if (!this.map) return;
    const visibility = isVisible ? 'visible' : 'none';

    if (layerKey === 'hazards') {
      ['hazards-clusters', 'hazards-cluster-count', 'hazards-points'].forEach((l) => {
        if (this.map.getLayer(l)) this.map.setLayoutProperty(l, 'visibility', visibility);
      });
    } else if (layerKey === 'cyber') {
      ['cyber-halo', 'cyber-points'].forEach((l) => {
        if (this.map.getLayer(l)) this.map.setLayoutProperty(l, 'visibility', visibility);
      });
    } else if (layerKey === 'news') {
      if (this.map.getLayer('news-points')) this.map.setLayoutProperty('news-points', 'visibility', visibility);
    } else if (layerKey === 'infrastructure') {
      if (this.map.getLayer('infrastructure-points')) this.map.setLayoutProperty('infrastructure-points', 'visibility', visibility);
    }
  }

  updateHudCounts() {
    const el = document.getElementById('map-telemetry-hud');
    if (el) {
      el.innerText = `HAZARDS: ${this.dataSources.hazards.features.length} | CYBER: ${this.dataSources.cyber.features.length} | NEWS: ${this.dataSources.news.features.length} | INFRA: ${this.dataSources.infrastructure.features.length}`;
    }
  }

  renderFallback(container) {
    container.innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; min-height:400px; background:#070A10; color:#00E5FF; font-family:'JetBrains Mono',monospace; padding:24px; text-align:center;">
        <div style="font-size:16px; font-weight:700; margin-bottom:8px; letter-spacing:0.05em;">[ EOD TACTICAL GEOSPATIAL MAP ]</div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:16px;">CARTO DARK MATTER TILESET // SUPERCLUSTER CLUSTERING ENGINE</div>
        <div style="display:flex; gap:16px; font-size:11px; color:var(--text-medium); flex-wrap:wrap; justify-content:center;">
          <span style="color:#EF4444;">● HAZARDS: USGS & NASA EONET</span>
          <span style="color:#00E5FF;">● CYBER: CISA ADVISORIES</span>
          <span style="color:#10B981;">● NEWS: GEOLOCATED RSS</span>
          <span style="color:#D4AF37;">● INFRASTRUCTURE: SCADA ASSETS</span>
        </div>
      </div>
    `;
  }
}
