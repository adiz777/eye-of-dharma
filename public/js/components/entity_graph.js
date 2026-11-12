// public/js/components/entity_graph.js
// EYE OF DHARMA (EOD) — Cytoscape.js Entity Relationship Graph Component
// Enforces Requirement R4 Confidence Edge Styles: VERIFIED (solid cyan), INFERRED (dashed amber), HYPOTHESIS (dotted gold)

export const CYTOSCAPE_EDGE_STYLES = {
  VERIFIED: { lineStyle: 'solid', color: '#00E5FF', width: 2.5 },
  INFERRED: { lineStyle: 'dashed', color: '#FFA726', width: 2.0 },
  HYPOTHESIS: { lineStyle: 'dotted', color: '#D4AF37', width: 1.5 }
};

export class EntityGraph {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.options = options;
    this.cy = null;
    this.caseId = options.caseId || 'case-00000000-0000-0000-0000-000000000001';
  }

  async init() {
    if (typeof document === 'undefined') return;
    const container = document.getElementById(this.containerId);
    if (!container) return;

    if (typeof window === 'undefined' || typeof window.cytoscape === 'undefined') {
      this.renderFallback(container);
      return;
    }

    try {
      this.cy = window.cytoscape({
        container: container,
        boxSelectionEnabled: false,
        autounselectify: false,
        style: this.getStylesheet(),
        elements: { nodes: [], edges: [] }
      });

      this.bindEvents();
      await this.loadCaseGraph(this.caseId);
    } catch (err) {
      console.warn('[EntityGraph] Failed to init cytoscape, rendering fallback:', err);
      this.renderFallback(container);
    }
  }

  /**
   * Cytoscape Stylesheet enforcing Requirement R4 Edge & Node Semantics
   */
  getStylesheet() {
    return [
      // Base Node Style
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#F8FAFC',
          'font-family': '"JetBrains Mono", monospace',
          'font-size': '10px',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'background-color': '#162036',
          'border-width': 1.5,
          'border-color': '#1E293B',
          'width': 36,
          'height': 36,
          'text-background-color': '#0A0D14',
          'text-background-opacity': 0.8,
          'text-background-padding': '2px',
          'text-background-shape': 'roundrectangle'
        }
      },
      // Entity Type Specific Shapes
      { selector: 'node[type = "ACTOR"], node[type = "ORGANIZATION"]', style: { 'shape': 'round-rectangle', 'border-color': '#EF4444' } },
      { selector: 'node[type = "DOMAIN"], node[type = "IP_ADDRESS"]', style: { 'shape': 'barrel', 'border-color': '#00E5FF' } },
      { selector: 'node[type = "MALWARE"], node[type = "VULNERABILITY"]', style: { 'shape': 'diamond', 'border-color': '#FFA726' } },
      { selector: 'node[type = "INFRASTRUCTURE"]', style: { 'shape': 'bottom-round-rectangle', 'border-color': '#D4AF37' } },
      { selector: 'node[type = "CERTIFICATE"]', style: { 'shape': 'tag', 'border-color': '#10B981' } },

      // High Risk Node Halo
      { selector: 'node[riskScore >= 80]', style: { 'border-color': '#EF4444', 'border-width': 2.5 } },
      { selector: 'node[riskScore >= 50][riskScore < 80]', style: { 'border-color': '#FFA726', 'border-width': 2.0 } },

      // Node Selected State
      { selector: 'node:selected', style: { 'border-color': '#00E5FF', 'border-width': 3, 'background-color': '#1E2B48' } },

      // Base Edge Style
      {
        selector: 'edge',
        style: {
          'label': 'data(label)',
          'color': '#94A3B8',
          'font-family': '"JetBrains Mono", monospace',
          'font-size': '8px',
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 1.0,
          'text-rotation': 'autorotate',
          'text-background-color': '#0A0D14',
          'text-background-opacity': 0.85,
          'text-background-padding': '2px'
        }
      },

      // Requirement R4: VERIFIED Relationships (Solid Cyan)
      {
        selector: 'edge[status = "VERIFIED"]',
        style: {
          'line-style': 'solid',
          'width': 2.5,
          'line-color': '#00E5FF',
          'target-arrow-color': '#00E5FF',
          'opacity': 1.0
        }
      },

      // Requirement R4: INFERRED Relationships (Dashed Amber)
      {
        selector: 'edge[status = "INFERRED"]',
        style: {
          'line-style': 'dashed',
          'line-dash-pattern': [6, 4],
          'width': 2.0,
          'line-color': '#FFA726',
          'target-arrow-color': '#FFA726',
          'opacity': 0.85
        }
      },

      // Requirement R4: HYPOTHESIS Relationships (Dotted Gold)
      {
        selector: 'edge[status = "HYPOTHESIS"]',
        style: {
          'line-style': 'dotted',
          'line-dash-pattern': [2, 4],
          'width': 1.5,
          'line-color': '#D4AF37',
          'target-arrow-color': '#D4AF37',
          'opacity': 0.65
        }
      },

      // Edge Selected State
      { selector: 'edge:selected', style: { 'width': 3.5, 'opacity': 1.0 } }
    ];
  }

  async loadCaseGraph(caseId) {
    try {
      const res = await fetch(`/api/v1/cases/${caseId}/graph`);
      const json = await res.json();
      if (!json.success || !json.elements) return;

      if (this.cy) {
        this.cy.elements().remove();
        this.cy.add(json.elements);
        this.runLayout('cose');
      }
    } catch (err) {
      console.error('[EntityGraph] Failed to load case graph:', err);
    }
  }

  runLayout(name = 'cose') {
    if (!this.cy) return;
    try {
      const layout = this.cy.layout({
        name: name,
        animate: true,
        animationDuration: 500,
        fit: true,
        padding: 30
      });
      layout.run();
    } catch {
      // Fallback to concentric/grid if cose not loaded
      const fallbackLayout = this.cy.layout({ name: 'grid', fit: true });
      fallbackLayout.run();
    }
  }

  bindEvents() {
    if (!this.cy) return;

    this.cy.on('tap', 'node', (e) => {
      const node = e.target;
      this.openInspector(node.data());
    });

    this.cy.on('tap', (e) => {
      if (e.target === this.cy) {
        this.closeInspector();
      }
    });

    this.cy.on('dbltap', 'node', async (e) => {
      const entityId = e.target.id();
      await this.expandNeighborhood(entityId);
    });

    this.cy.on('zoom', () => {
      const zoom = this.cy.zoom();
      if (zoom < 0.6) {
        this.cy.style().selector('edge').style('label', '').update();
      } else {
        this.cy.style().selector('edge').style('label', 'data(label)').update();
      }
    });
  }

  async expandNeighborhood(entityId) {
    try {
      const res = await fetch(`/api/v1/entities/${entityId}/graph`);
      const json = await res.json();
      if (!json.success || !json.elements || !this.cy) return;

      const existing = new Set(this.cy.elements().map((el) => el.id()));
      const toAdd = [
        ...(json.elements.nodes || []).filter((n) => !existing.has(n.data.id)),
        ...(json.elements.edges || []).filter((e) => !existing.has(e.data.id))
      ];

      if (toAdd.length > 0) {
        this.cy.add(toAdd);
        this.runLayout('cose');
      }
    } catch (err) {
      console.error('[EntityGraph] Expansion failed:', err);
    }
  }

  openInspector(data) {
    let drawer = document.getElementById('entity-inspector-drawer');
    const parentContainer = this.cy?.container()?.parentElement;
    if (!parentContainer) return;

    if (!drawer) {
      drawer = document.createElement('div');
      drawer.id = 'entity-inspector-drawer';
      drawer.style.cssText =
        'position:absolute; right:0; top:0; bottom:0; width:300px; background:#0F172A; border-left:1px solid #1E293B; padding:16px; font-family:var(--font-sans); color:#F8FAFC; z-index:10; overflow-y:auto;';
      parentContainer.style.position = 'relative';
      parentContainer.appendChild(drawer);
    }

    drawer.style.display = 'block';
    drawer.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <span style="font-size:11px; font-weight:700; color:#00E5FF; text-transform:uppercase;">[${data.type || 'ENTITY'}]</span>
        <button id="close-inspector-btn" style="background:transparent; border:none; color:#94A3B8; font-size:16px; cursor:pointer;">✕</button>
      </div>
      <div style="font-size:15px; font-weight:700; margin-bottom:6px;">${data.label || data.name}</div>
      <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#94A3B8; background:#0A0D14; padding:6px; border-radius:4px; margin-bottom:12px; word-break:break-all;">
        ${data.value || data.id}
      </div>
      <div style="margin-bottom:12px;">
        <div style="font-size:10px; color:#94A3B8; margin-bottom:4px; text-transform:uppercase;">Risk Score</div>
        <div style="font-size:18px; font-weight:700; color:${(data.riskScore || 0) >= 80 ? '#EF4444' : (data.riskScore || 0) >= 50 ? '#FFA726' : '#00E5FF'};">
          ${data.riskScore || 0} / 100
        </div>
      </div>
      <div style="display:flex; flex-direction:column; gap:8px; margin-top:20px;">
        <button id="btn-expand-entity" class="btn btn-secondary" style="font-size:11px;">
          Expand 1-Hop Neighborhood
        </button>
      </div>
    `;

    document.getElementById('close-inspector-btn')?.addEventListener('click', () => this.closeInspector());
    document.getElementById('btn-expand-entity')?.addEventListener('click', () => this.expandNeighborhood(data.id));
  }

  closeInspector() {
    const drawer = document.getElementById('entity-inspector-drawer');
    if (drawer) drawer.style.display = 'none';
  }

  renderFallback(container) {
    container.innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; min-height:450px; background:#070A10; color:#00E5FF; font-family:'JetBrains Mono',monospace; padding:20px; text-align:center;">
        <div style="font-size:16px; font-weight:700; margin-bottom:8px;">[ CYTOSCAPE.JS ENTITY RELATIONSHIP GRAPH ]</div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:16px;">3-TIER CONFIDENCE TOPOLOGY ENGINE READY</div>
        <div style="display:flex; gap:16px; font-size:11px; flex-wrap:wrap; justify-content:center;">
          <span style="color:#00E5FF;">— SOLID: VERIFIED (0.9+)</span>
          <span style="color:#FFA726;">- - DASHED: INFERRED (0.5 - 0.89)</span>
          <span style="color:#D4AF37;">··· DOTTED: HYPOTHESIS (&lt; 0.5)</span>
        </div>
      </div>
    `;
  }
}
