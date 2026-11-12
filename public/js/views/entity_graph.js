// public/js/views/entity_graph.js
// EYE OF DHARMA (EOD) — Interactive Entity Graph View

import { EntityGraph } from '../components/entity_graph.js';

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[GRAPH]</span> Entity Graph</h1>
        <div class="view-subtitle font-mono">CYTOSCAPE.JS INTERACTIVE RELATIONSHIP TOPOLOGY & CONFIDENCE EDGES</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-info font-mono">CASE: ARCTIC PHOENIX</span>
      </div>
    </div>

    <div class="graph-shell font-mono">
      <!-- Toolbar -->
      <div class="graph-toolbar">
        <div style="display:flex; align-items:center; gap:16px;">
          <span style="color:var(--text-muted); font-size:10px;">EDGE CONFIDENCE:</span>
          <span style="color:var(--accent-cyan); font-weight:700;">— Solid: Verified (0.9+)</span>
          <span style="color:var(--status-inferred); font-weight:700;">- - Dashed: Inferred (0.5-0.89)</span>
          <span style="color:var(--accent-gold); font-weight:700;">··· Dotted: Hypothesis (&lt;0.5)</span>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-secondary" id="graph-relayout-btn" style="padding:2px 8px; font-size:10px;">Auto Layout</button>
        </div>
      </div>

      <!-- Graph Canvas Container -->
      <div id="cy-main-container" class="graph-container"></div>
    </div>
  `;

  const graph = new EntityGraph('cy-main-container', {
    caseId: 'case-00000000-0000-0000-0000-000000000001'
  });
  graph.init();

  container.querySelector('#graph-relayout-btn')?.addEventListener('click', () => {
    graph.runLayout('cose');
  });
}
