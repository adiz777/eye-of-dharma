// public/js/views/timeline.js
// EYE OF DHARMA (EOD) — Chronological Timeline View

import { TimelineView } from '../components/timeline_view.js';

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[TIME]</span> Timeline</h1>
        <div class="view-subtitle font-mono">CHRONOLOGICAL INCIDENT RECONSTRUCTION & MULTI-SOURCE SWIMLANES</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-info font-mono">CHRONOLOGY: UTC ZULU</span>
      </div>
    </div>

    <div class="card" style="margin-top:12px;">
      <div id="timeline-mount-point"></div>
    </div>
  `;

  const timeline = new TimelineView('timeline-mount-point');
  timeline.init();
}
