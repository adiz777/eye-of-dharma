// public/js/components/timeline_view.js
// EYE OF DHARMA (EOD) — Chronological Investigation Timeline with Swimlanes
import { esc } from '../escape.js';

export class TimelineView {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.options = options;
    this.events = [];
    this.lanes = [
      { id: 'THREATS', title: 'CYBER THREATS & KEV', color: '#EF4444' },
      { id: 'HAZARDS', title: 'GEOSPATIAL & HAZARDS', color: '#F59E0B' },
      { id: 'OSINT', title: 'PUBLIC OSINT & FEEDS', color: '#00E5FF' },
      { id: 'INVESTIGATION', title: 'CASE EVIDENCE & ACTIONS', color: '#10B981' }
    ];
  }

  async init() {
    if (typeof document === 'undefined') return;
    const container = document.getElementById(this.containerId);
    if (!container) return;

    this.render(container);
    await this.fetchTimelineData();
  }

  async fetchTimelineData() {
    try {
      const res = await fetch('/api/v1/feeds?limit=60');
      const data = await res.json();
      if (data && data.items) {
        this.events = data.items.map((item) => {
          let lane = 'OSINT';
          if (item.category === 'EARTHQUAKE' || item.category === 'HAZARD') lane = 'HAZARDS';
          else if (item.category === 'VULNERABILITY' || item.category === 'ADVISORY') lane = 'THREATS';

          return {
            id: item.id,
            title: item.title,
            lane,
            timestamp: item.published_at || new Date().toISOString(),
            severity: item.severity || 'MEDIUM',
            source: item.feed_name || item.category,
            verificationStatus: 'Observed'
          };
        });

        this.events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        this.updateEvents();
      }
    } catch (err) {
      console.warn('[TimelineView] Error fetching events:', err);
    }
  }

  render(container) {
    container.innerHTML = `
      <div class="timeline-shell font-mono">
        <div class="card-header" style="margin-bottom:12px;">
          <div>
            <span class="card-title">Chronological Investigation Swimlanes</span>
            <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">UTC ZULU INCIDENT RECONSTRUCTION</div>
          </div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="badge badge-info" id="timeline-event-count">0 EVENTS</span>
          </div>
        </div>

        <div class="timeline-swimlanes" id="timeline-lanes-container">
          ${this.lanes
            .map(
              (lane) => `
            <div class="timeline-lane" data-lane-id="${lane.id}">
              <div class="timeline-lane-title" style="color:${lane.color};">
                ● ${lane.title}
              </div>
              <div class="timeline-events-track" id="track-${lane.id}">
                <span style="color:var(--text-disabled); font-size:11px;">Loading chronological events...</span>
              </div>
            </div>
          `
            )
            .join('')}
        </div>
      </div>
    `;
  }

  updateEvents() {
    const countEl = document.getElementById('timeline-event-count');
    if (countEl) countEl.innerText = `${this.events.length} EVENTS`;

    for (const lane of this.lanes) {
      const track = document.getElementById(`track-${lane.id}`);
      if (!track) continue;

      const laneEvents = this.events.filter((e) => e.lane === lane.id);
      if (laneEvents.length === 0) {
        track.innerHTML = `<span style="color:var(--text-disabled); font-size:11px;">No chronological events recorded</span>`;
        continue;
      }

      track.innerHTML = laneEvents
        .slice(0, 15)
        .map(
          (ev) => `
          <div class="timeline-event-card">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px; font-size:10px;">
              <span style="color:var(--accent-cyan); font-weight:700;">[${esc(ev.source)}]</span>
              <span style="color:var(--text-muted);">${ev.timestamp.substring(11, 19)}Z</span>
            </div>
            <div style="color:var(--text-high); font-weight:600; line-height:1.2; margin-bottom:6px;">${esc(ev.title)}</div>
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:9px;">
              <span class="badge badge-${ev.severity === 'CRITICAL' ? 'critical' : 'info'}">${ev.severity}</span>
              <span style="color:var(--status-verified);">✓ ${ev.verificationStatus}</span>
            </div>
          </div>
        `
        )
        .join('');
    }
  }
}
