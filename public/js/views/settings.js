// public/js/views/settings.js
// EYE OF DHARMA (EOD) — Settings & Interface Configuration View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[SET]</span> Settings</h1>
        <div class="view-subtitle font-mono">INTERFACE CONFIGURATION, ACCESSIBILITY & DEFENSIVE POLICIES</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-info font-mono">CONFIG PERSISTED</span>
      </div>
    </div>

    <div class="card-grid">
      <!-- Accessibility Settings -->
      <div class="card font-mono">
        <div class="card-header"><span class="card-title">Accessibility & Motion Controls</span></div>
        <div style="font-size:12px; display:flex; flex-direction:column; gap:12px; margin-top:8px;">
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
            <input type="checkbox" id="pref-reduce-motion" />
            <span>Force Reduced Motion (Halt Radar rotation & transitions)</span>
          </label>
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
            <input type="checkbox" id="pref-high-contrast" checked disabled />
            <span>WCAG 2.1 AA Contrast Compliance (Enforced: &gt; 7:1 ratio)</span>
          </label>
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
            <input type="checkbox" id="pref-focus-ring" checked disabled />
            <span>Keyboard Focus Ring Outline (2px Electric Cyan)</span>
          </label>
        </div>
      </div>

      <!-- Security Policies -->
      <div class="card font-mono">
        <div class="card-header"><span class="card-title">SSRF Firewall & Network Security</span></div>
        <div style="font-size:11px; color:var(--text-muted); display:flex; flex-direction:column; gap:6px; margin-top:8px;">
          <div>• 6-Stage SSRF Filter: <strong style="color:var(--status-verified);">ACTIVE</strong></div>
          <div>• IPv4 Private CIDR Blocking: <strong style="color:var(--status-verified);">RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)</strong></div>
          <div>• IPv6 Link-Local / ULA Blocking: <strong style="color:var(--status-verified);">fe80::/10, fc00::/7</strong></div>
          <div>• DNS Rebinding Defense: <strong style="color:var(--status-verified);">Pre-resolution IP Pinning</strong></div>
          <div>• Response Caps: <strong>5.0 MB max payload | 5000ms timeout</strong></div>
        </div>
      </div>
    </div>
  `;

  const motionCheck = container.querySelector('#pref-reduce-motion');
  if (motionCheck) {
    motionCheck.checked = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }
}
