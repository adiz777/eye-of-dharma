// public/js/components/event_ticker.js
// EYE OF DHARMA (EOD) — Live Intelligence Event Ticker with Speed & Pause Controls
import { esc } from '../escape.js';

export class EventTicker {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.pollIntervalMs = options.pollIntervalMs || 5000;
    this.speed = 1.0; // 1x, 2x, 5x
    this.isPaused = false;
    this.isHovered = false;
    this.filterSeverity = 'ALL';
    this.events = [];
    this.pollTimer = null;
    this.offset = 0;
    this.animId = null;
    this.track = null;
    this.viewport = null;
  }

  init() {
    if (typeof document === 'undefined') return;
    this.container = document.getElementById(this.containerId);
    if (!this.container) return;

    this.renderShell();
    this.bindControls();
    this.fetchEvents();
    this.startPolling();
    this.startAnimation();
  }

  renderShell() {
    this.container.innerHTML = `
      <div class="ticker-wrapper" style="display:flex; align-items:center; height:36px; background:#0F172A; border-bottom:1px solid #1E293B; color:#F8FAFC; font-family:'JetBrains Mono',monospace; font-size:11px; overflow:hidden; width:100%;">
        <!-- Left HUD Badge -->
        <div style="display:flex; align-items:center; gap:8px; padding:0 12px; background:#162036; height:100%; border-right:1px solid #1E293B; white-space:nowrap; z-index:2;">
          <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#00E5FF; box-shadow:0 0 6px #00E5FF;"></span>
          <span style="color:#00E5FF; font-weight:700;">LIVE OSINT FEED</span>
          <span id="ticker-count-pill" style="font-size:10px; color:#94A3B8;">(0)</span>
        </div>

        <!-- Scrolling Events Track -->
        <div id="ticker-viewport" style="flex:1; overflow:hidden; position:relative; height:100%; display:flex; align-items:center;" role="region" aria-live="polite">
          <div id="ticker-track" style="display:inline-flex; align-items:center; white-space:nowrap; will-change:transform;"></div>
        </div>

        <!-- Right Controls -->
        <div style="display:flex; align-items:center; gap:6px; padding:0 10px; background:#162036; height:100%; border-left:1px solid #1E293B; z-index:2;">
          <button id="ticker-pause-btn" title="Pause / Resume" style="background:#0A0D14; border:1px solid #1E293B; color:#00E5FF; padding:2px 8px; font-size:11px; border-radius:3px; cursor:pointer;">❚❚</button>
          <button id="ticker-speed-btn" title="Speed multiplier" style="background:#0A0D14; border:1px solid #1E293B; color:#CBD5E1; padding:2px 6px; font-size:10px; border-radius:3px; cursor:pointer;">1x</button>
          <select id="ticker-severity-filter" style="background:#0A0D14; border:1px solid #1E293B; color:#CBD5E1; font-size:10px; padding:2px 4px; border-radius:3px;">
            <option value="ALL">ALL SEV</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
          </select>
        </div>
      </div>
    `;

    this.track = document.getElementById('ticker-track');
    this.viewport = document.getElementById('ticker-viewport');
  }

  bindControls() {
    const pauseBtn = document.getElementById('ticker-pause-btn');
    pauseBtn?.addEventListener('click', () => {
      this.isPaused = !this.isPaused;
      pauseBtn.innerText = this.isPaused ? '▶' : '❚❚';
    });

    const speedBtn = document.getElementById('ticker-speed-btn');
    const speeds = [1.0, 2.0, 5.0];
    speedBtn?.addEventListener('click', () => {
      const nextIdx = (speeds.indexOf(this.speed) + 1) % speeds.length;
      this.speed = speeds[nextIdx];
      speedBtn.innerText = `${this.speed}x`;
    });

    const sevFilter = document.getElementById('ticker-severity-filter');
    sevFilter?.addEventListener('change', (e) => {
      this.filterSeverity = e.target.value;
      this.renderTrackItems();
    });

    this.viewport?.addEventListener('mouseenter', () => { this.isHovered = true; });
    this.viewport?.addEventListener('mouseleave', () => { this.isHovered = false; });
  }

  async fetchEvents() {
    try {
      const res = await fetch('/api/v1/feeds?limit=50');
      const data = await res.json();
      if (!data.success || !Array.isArray(data.items)) return;

      const existingIds = new Set(this.events.map((e) => e.id));
      const newItems = data.items.filter((i) => !existingIds.has(i.id));

      if (newItems.length > 0 || this.events.length === 0) {
        this.events = [...newItems, ...this.events].slice(0, 150);
        this.renderTrackItems();
        const countPill = document.getElementById('ticker-count-pill');
        if (countPill) countPill.innerText = `(${this.events.length})`;
      }
    } catch (err) {
      console.warn('[EventTicker] Polling failed:', err);
    }
  }

  renderTrackItems() {
    if (!this.track) return;
    const filtered =
      this.filterSeverity === 'ALL'
        ? this.events
        : this.events.filter((e) => e.severity === this.filterSeverity);

    if (filtered.length === 0) {
      this.track.innerHTML = `<span style="padding:0 20px; color:#64748B;">[ NO RECENT INTELLIGENCE EVENTS ]</span>`;
      return;
    }

    const html = filtered
      .map((item) => {
        const sevColor =
          {
            CRITICAL: '#EF4444',
            HIGH: '#F59E0B',
            MEDIUM: '#38BDF8',
            LOW: '#64748B',
            INFO: '#64748B'
          }[item.severity] || '#64748B';

        const timeStr = item.published_at ? item.published_at.substring(11, 19) + 'Z' : '';

        return `
        <div class="ticker-item" data-id="${item.id}" tabindex="0" style="display:inline-flex; align-items:center; gap:8px; padding:0 18px; border-right:1px solid #1E293B; cursor:pointer;">
          <span style="color:#00E5FF; font-weight:700;">[${esc(item.feed_name || item.category)}]</span>
          <span style="color:${sevColor}; font-weight:700;">${item.severity}</span>
          <span style="color:#F8FAFC;">${esc(item.title)}</span>
          ${timeStr ? `<span style="color:#64748B;">${timeStr}</span>` : ''}
        </div>
      `;
      })
      .join('');

    // Duplicate track content once to support seamless infinite loop
    this.track.innerHTML = html + html;

    this.track.querySelectorAll('.ticker-item').forEach((el) => {
      el.addEventListener('click', () => {
        const id = el.getAttribute('data-id');
        const ev = this.events.find((x) => x.id === id);
        if (ev) this.showEventModal(ev);
      });
    });
  }

  showEventModal(ev) {
    // Ticker items link straight to their original evidence.
    if (/^https?:\/\//i.test(ev.source_url || '')) window.open(ev.source_url, '_blank', 'noopener,noreferrer');
  }

  startPolling() {
    this.pollTimer = setInterval(() => this.fetchEvents(), this.pollIntervalMs);
  }

  startAnimation() {
    if (typeof window === 'undefined') return;
    let lastTime = performance.now();
    const step = (now) => {
      const dt = (now - lastTime) / 1000;
      lastTime = now;

      if (!this.isPaused && !this.isHovered && this.track) {
        const baseSpeed = 40; // 40px/s at 1x
        this.offset -= baseSpeed * this.speed * dt;

        const halfWidth = this.track.scrollWidth / 2;
        if (halfWidth > 0 && Math.abs(this.offset) >= halfWidth) {
          this.offset = 0;
        }

        this.track.style.transform = `translateX(${this.offset}px)`;
      }

      this.animId = requestAnimationFrame(step);
    };
    this.animId = requestAnimationFrame(step);
  }

  destroy() {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.animId) cancelAnimationFrame(this.animId);
  }
}
