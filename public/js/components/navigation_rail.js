// public/js/components/navigation_rail.js
// EYE OF DHARMA (EOD) — 15 Module Navigation Rail Component

export const NAVIGATION_MODULES = [
  { id: 'command-center', path: '/command-center', name: 'Command Centre', code: 'CMD', icon: '📊' },
  { id: 'global-monitor', path: '/global-monitor', name: 'Global Monitor', code: 'MAP', icon: '🌐' },
  { id: 'live-intel', path: '/live-intel', name: 'Live Intelligence', code: 'INTEL', icon: '📡' },
  { id: 'cyber-threats', path: '/cyber-threats', name: 'Cyber Threats', code: 'CYBER', icon: '🛡️' },
  { id: 'investigations', path: '/investigations', name: 'Investigations', code: 'INVST', icon: '⚡' },
  { id: 'cases', path: '/cases', name: 'Cases', code: 'CASES', icon: '📁' },
  { id: 'entity-graph', path: '/entity-graph', name: 'Entity Graph', code: 'GRAPH', icon: '🕸️' },
  { id: 'timeline', path: '/timeline', name: 'Timeline', code: 'TIME', icon: '⏱️' },
  { id: 'ai-ops', path: '/ai-ops', name: 'AI Operations', code: 'AI', icon: '🤖' },
  { id: 'watchlists', path: '/watchlists', name: 'Watchlists', code: 'WATCH', icon: '🎯' },
  { id: 'reports', path: '/reports', name: 'Reports', code: 'REPRT', icon: '📄' },
  { id: 'data-sources', path: '/data-sources', name: 'Data Sources', code: 'SRCS', icon: '🔌' },
  { id: 'audit-logs', path: '/audit-logs', name: 'Audit Logs', code: 'AUDIT', icon: '🔒' },
  { id: 'settings', path: '/settings', name: 'Settings', code: 'SET', icon: '⚙️' },
  { id: 'system-health', path: '/system-health', name: 'System Health', code: 'HLTH', icon: '💚' }
];

export class NavigationRail {
  constructor(railElementId = 'nav-rail') {
    this.railElementId = railElementId;
    this.rail = null;
    this.isCollapsed = false;
  }

  init() {
    if (typeof document === 'undefined') return;
    this.rail = document.getElementById(this.railElementId);
    if (!this.rail) return;

    this.render();
    this.bindEvents();
  }

  render() {
    if (!this.rail) return;
    this.rail.innerHTML = `
      <div class="nav-rail-header">
        <span class="nav-rail-title">Operations Deck</span>
        <button id="rail-collapse-btn" class="nav-rail-toggle" aria-label="Collapse Navigation Rail" title="Collapse Rail (Ctrl+B)">
          <span>◀</span>
        </button>
      </div>

      <ul class="nav-rail-list font-mono" role="menubar">
        ${NAVIGATION_MODULES.map(
          (m) => `
          <li class="nav-item" role="none">
            <a href="${m.path}" class="nav-link" data-route="${m.path}" role="menuitem">
              <span class="nav-icon" aria-hidden="true">${m.code}</span>
              <span class="nav-label">${m.name.toUpperCase()}</span>
              ${m.badge ? `<span class="nav-badge ${m.badge.type === 'alert' ? 'alert' : ''}">${m.badge.text}</span>` : ''}
            </a>
          </li>
        `
        ).join('')}
      </ul>
    `;
  }

  bindEvents() {
    const collapseBtn = document.getElementById('rail-collapse-btn');
    collapseBtn?.addEventListener('click', () => this.toggleCollapse());

    // Ctrl+B shortcut for rail toggle
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'b' || e.key === 'B')) {
        e.preventDefault();
        this.toggleCollapse();
      }
    });

    // Mobile menu toggle
    const mobileToggle = document.getElementById('mobile-menu-toggle');
    const backdrop = document.getElementById('nav-backdrop');

    mobileToggle?.addEventListener('click', () => {
      this.rail?.classList.toggle('mobile-open');
      backdrop?.classList.toggle('active');
    });

    backdrop?.addEventListener('click', () => {
      this.rail?.classList.remove('mobile-open');
      backdrop?.classList.remove('active');
    });
  }

  toggleCollapse() {
    if (!this.rail) return;
    this.isCollapsed = !this.isCollapsed;
    this.rail.classList.toggle('collapsed', this.isCollapsed);
    const collapseBtn = document.getElementById('rail-collapse-btn');
    if (collapseBtn) {
      collapseBtn.innerHTML = this.isCollapsed ? '<span>▶</span>' : '<span>◀</span>';
      collapseBtn.setAttribute(
        'aria-label',
        this.isCollapsed ? 'Expand Navigation Rail' : 'Collapse Navigation Rail'
      );
    }

    // Trigger window resize so charts/canvases/maps resize
    window.dispatchEvent(new Event('resize'));
  }

  setActive(path) {
    if (!this.rail) return;
    const links = this.rail.querySelectorAll('.nav-link');
    links.forEach((link) => {
      const route = link.getAttribute('data-route');
      if (route === path || (path !== '/' && path.startsWith(`${route}/`))) {
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
      } else {
        link.classList.remove('active');
        link.removeAttribute('aria-current');
      }
    });
  }
}
