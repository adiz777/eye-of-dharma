// public/js/views/command_center.js
// EYE OF DHARMA (EOD) — Command Centre View

import { RadarSweep } from '../components/radar_sweep.js';
import { mountTerminalConsole } from '../components/terminal_console.js';

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[CMD]</span> Command Centre</h1>
        <div class="view-subtitle font-mono">EXECUTIVE OPERATIONAL POSTURE & TACTICAL METRICS</div>
      </div>
      <div class="view-actions">
        <span class="status-dot pulsing"></span>
        <span class="font-mono" style="font-size:11px; margin-left:6px; color:var(--text-muted)">LIVE TELEMETRY ACTIVE</span>
      </div>
    </div>

    <!-- Top KPI Card Grid -->
    <div class="card-grid">
      <div class="card">
        <div class="card-header"><span class="card-title">Live Feed Records</span><span class="font-mono" style="color:var(--accent-cyan)" id="cmd-feed-fresh">--</span></div>
        <div class="card-metric font-mono" style="color:var(--accent-cyan)" id="cmd-feed-count">--</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:6px;" id="cmd-feed-breakdown">Public sources: USGS, NASA EONET, CISA, RSS</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Cases</span><span class="font-mono" style="color:var(--text-muted)" id="cmd-cases-synth"></span></div>
        <div class="card-metric font-mono" style="color:var(--text-high)" id="cmd-cases-count">--</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Persistent investigations in local ledger</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Evidence Ledger</span><span class="font-mono" style="color:var(--accent-gold)">APPEND-ONLY</span></div>
        <div class="card-metric font-mono" style="color:var(--accent-gold)" id="cmd-evidence-count">--</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">SHA-256 fingerprinted, DB-trigger protected</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Agent Runs</span><span class="font-mono" style="color:var(--text-muted)">RECORDED</span></div>
        <div class="card-metric font-mono" style="color:var(--text-high)" id="cmd-runs-count">--</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Deterministic fallback when no LLM is configured</div>
      </div>
    </div>

    <!-- Center Operational Stage: Radar Canvas + Terminal Console HUD -->
    <div style="display:grid; grid-template-columns:360px 1fr; gap:16px; margin-top:16px;" id="cmd-stage-grid">
      <!-- 15 RPM Radar Sweep -->
      <div class="radar-shell">
        <div class="card-header" style="width:100%; margin-bottom:8px;">
          <span class="card-title">RADAR VIEW · MAPPED FEED EVENTS</span>
          <span class="badge badge-info font-mono" title="Visualisation of ingested records only; not a sensor">VISUALISATION</span>
        </div>
        <canvas id="cmd-radar-canvas" class="radar-canvas"></canvas>
      </div>

      <!-- Allowlisted Terminal Console -->
      <div id="cmd-terminal-mount"></div>
    </div>

    <!-- Quick Action Launch Bar -->
    <div class="card" style="margin-top:16px;">
      <div class="card-header"><span class="card-title">Tactical Action Quickbar</span></div>
      <div style="display:flex; gap:12px; flex-wrap:wrap;">
        <button class="btn btn-primary" id="btn-goto-cases">Open Case Ledger</button>
        <button class="btn btn-secondary" id="btn-goto-map">Launch Global Monitor</button>
        <button class="btn btn-secondary" id="btn-goto-investigations">Deploy Agent Task</button>
      </div>
    </div>
  `;

  // Initialize Radar Sweep
  const radar = new RadarSweep('cmd-radar-canvas', { rpm: 15.0 });
  radar.init();

  // Mount Terminal Console
  const termMount = container.querySelector('#cmd-terminal-mount');
  if (termMount) {
    mountTerminalConsole(termMount);
  }

  // Quick action navigation
  container.querySelector('#btn-goto-cases')?.addEventListener('click', () => {
    window.eodRouter?.navigate('/cases');
  });
  container.querySelector('#btn-goto-map')?.addEventListener('click', () => {
    window.eodRouter?.navigate('/global-monitor');
  });
  container.querySelector('#btn-goto-investigations')?.addEventListener('click', () => {
    window.eodRouter?.navigate('/investigations');
  });

  // Fetch real telemetry counts
  const set = (sel, v) => { const el = container.querySelector(sel); if (el) el.textContent = v; };
  fetch('/api/v1/system/status')
    .then((r) => r.json())
    .then((s) => {
      const t = s?.tables || {};
      const synth = s?.synthetic_counts || {};
      set('#cmd-cases-count', String(t.cases ?? 0));
      set('#cmd-evidence-count', String(t.evidence_ledger ?? 0));
      set('#cmd-runs-count', String(t.agent_runs ?? 0));
      if (synth.cases) set('#cmd-cases-synth', `${synth.cases} DEMO`);
    })
    .catch(() => {});
  fetch('/api/v1/feeds?limit=100')
    .then((r) => r.json())
    .then((f) => {
      set('#cmd-feed-count', String(f.total ?? 0));
      const by = {};
      for (const it of f.items || []) by[it.feed_name] = (by[it.feed_name] || 0) + 1;
      const parts = Object.entries(by).map(([k, v]) => `${k} ${v}`);
      if (parts.length) set('#cmd-feed-breakdown', `Latest 100: ${parts.join(' · ')}`);
      const newest = (f.items || []).map((i) => i.ingested_at).filter(Boolean).sort().pop();
      set('#cmd-feed-fresh', newest ? `INGESTED ${newest.slice(11, 16)}Z` : 'NO DATA YET');
    })
    .catch(() => set('#cmd-feed-fresh', 'UNAVAILABLE'));
}
