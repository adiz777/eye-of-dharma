// public/js/components/command_palette.js
// Global Ctrl+K Command Palette with fuzzy search, categories, and keyboard navigation

export const DEFAULT_COMMANDS = [
  // Navigation Modules
  { id: 'nav-command-center', title: 'Command Centre', description: 'Executive HUD & Alert Posture', category: 'navigation', route: '/command-center', icon: '📊', keywords: ['dashboard', 'home', 'kpi'] },
  { id: 'nav-global-monitor', title: 'Global Monitor', description: 'MapLibre GL Geospatial Deck', category: 'navigation', route: '/global-monitor', icon: '🌐', keywords: ['map', 'earthquakes', 'hazards'] },
  { id: 'nav-live-intel', title: 'Live Intelligence', description: 'Streaming OSINT Event Stream', category: 'navigation', route: '/live-intel', icon: '📡', keywords: ['feeds', 'events', 'stream'] },
  { id: 'nav-cyber-threats', title: 'Cyber Threats', description: 'CISA KEV Catalog & CVE Tracker', category: 'navigation', route: '/cyber-threats', icon: '🛡️', keywords: ['cve', 'kev', 'vulnerabilities'] },
  { id: 'nav-investigations', title: 'Investigations', description: 'Multi-Agent Investigation DAG', category: 'navigation', route: '/investigations', icon: '⚡', keywords: ['agents', 'runs', 'dharma'] },
  { id: 'nav-cases', title: 'Case Management', description: 'Active & Historical Investigations', category: 'navigation', route: '/cases', icon: '📁', keywords: ['dossier', 'evidence', 'case'] },
  { id: 'nav-entity-graph', title: 'Entity Graph', description: 'Cytoscape.js Relationship Network', category: 'navigation', route: '/entity-graph', icon: '🕸️', keywords: ['nodes', 'edges', 'network'] },
  { id: 'nav-timeline', title: 'Timeline', description: 'Chronological Provenance Stream', category: 'navigation', route: '/timeline', icon: '⏱️', keywords: ['chronology', 'swimlanes', 'history'] },
  { id: 'nav-ai-ops', title: 'AI Operations', description: 'Multi-Agent Personas & Telemetry', category: 'navigation', route: '/ai-ops', icon: '🤖', keywords: ['models', 'prompts', 'llm'] },
  { id: 'nav-watchlists', title: 'Watchlists', description: 'CIDR, Domain & Keyword Monitors', category: 'navigation', route: '/watchlists', icon: '🎯', keywords: ['alerts', 'cidr', 'monitors'] },
  { id: 'nav-reports', title: 'Reports Engine', description: 'Grounded Investigation Export', category: 'navigation', route: '/reports', icon: '📄', keywords: ['pdf', 'html', 'export'] },
  { id: 'nav-data-sources', title: 'Data Sources', description: 'OSINT Connectors Health & Latency', category: 'navigation', route: '/data-sources', icon: '🔌', keywords: ['connectors', 'usgs', 'cisa'] },
  { id: 'nav-audit-logs', title: 'Audit Logs', description: 'Immutable Cryptographic Audit Trail', category: 'navigation', route: '/audit-logs', icon: '🔒', keywords: ['integrity', 'compliance', 'ledger'] },
  { id: 'nav-settings', title: 'Settings', description: 'User Preferences & Theme Controls', category: 'navigation', route: '/settings', icon: '⚙️', keywords: ['config', 'theme', 'a11y'] },
  { id: 'nav-system-health', title: 'System Health', description: 'Telemetry, Memory & DB Metrics', category: 'navigation', route: '/system-health', icon: '💚', keywords: ['telemetry', 'memory', 'cpu'] },

  // Quick Actions
  { id: 'act-new-case', title: 'Create Investigation Case', description: 'Initialize a new investigation dossier', category: 'actions', action: 'create_case', icon: '➕', keywords: ['new', 'add', 'create'] },
  { id: 'act-footprint', title: 'Passive Footprint Query', description: 'Initiate non-intrusive target reconnaissance', category: 'actions', action: 'run_footprint', icon: '🔍', keywords: ['lookup', 'dns', 'rdap', 'whois'] },
  { id: 'act-terminal', title: 'Toggle Terminal HUD', description: 'Dock/undock allowlisted command console', category: 'actions', action: 'toggle_terminal', icon: '💻', keywords: ['cli', 'console', 'shell'] },
  { id: 'act-refresh-feeds', title: 'Sync Live Data Feeds', description: 'Trigger manual connector refresh', category: 'actions', action: 'refresh_feeds', icon: '🔄', keywords: ['update', 'fetch', 'poll'] }
];

/**
 * Pure scoring and filtering engine for command palette items
 */
export function filterCommands(query, items = DEFAULT_COMMANDS) {
  if (!query || !query.trim()) {
    return items.slice(0, 10);
  }

  const clean = query.toLowerCase().trim();
  const scored = [];

  for (const item of items) {
    let score = 0;
    const title = item.title.toLowerCase();
    const desc = (item.description || '').toLowerCase();
    const cat = item.category.toLowerCase();
    const keywords = (item.keywords || []).map((k) => k.toLowerCase());

    if (title === clean) {
      score += 100;
    } else if (title.startsWith(clean)) {
      score += 80;
    } else if (title.includes(clean)) {
      score += 60;
    }

    if (keywords.some((k) => k === clean)) {
      score += 50;
    } else if (keywords.some((k) => k.includes(clean))) {
      score += 30;
    }

    if (desc.includes(clean)) {
      score += 25;
    }

    if (cat.includes(clean)) {
      score += 15;
    }

    if (score > 0) {
      scored.push({ item, score });
    }
  }

  return scored
    .sort((a, b) => b.score - a.score)
    .map((s) => s.item);
}

/**
 * Command Palette State Controller
 */
export class CommandPaletteController {
  constructor(options = {}) {
    this.items = options.items || [...DEFAULT_COMMANDS];
    this.isOpen = false;
    this.query = '';
    this.results = [];
    this.selectedIndex = 0;
    this.onSelect = options.onSelect || (() => {});
    this.onClose = options.onClose || (() => {});
  }

  open() {
    this.isOpen = true;
    this.query = '';
    this.results = filterCommands('', this.items);
    this.selectedIndex = 0;
  }

  close() {
    this.isOpen = false;
    this.query = '';
    this.results = [];
    this.selectedIndex = 0;
    this.onClose();
  }

  setQuery(q) {
    this.query = q;
    this.results = filterCommands(q, this.items);
    this.selectedIndex = 0;
  }

  next() {
    if (this.results.length === 0) return;
    this.selectedIndex = (this.selectedIndex + 1) % this.results.length;
  }

  prev() {
    if (this.results.length === 0) return;
    this.selectedIndex = (this.selectedIndex - 1 + this.results.length) % this.results.length;
  }

  getSelected() {
    if (this.results.length === 0) return null;
    return this.results[this.selectedIndex] || null;
  }

  execute() {
    const selected = this.getSelected();
    if (selected) {
      this.close();
      this.onSelect(selected);
      return selected;
    }
    return null;
  }

  addItems(newItems) {
    this.items = [...this.items, ...newItems];
  }
}

/**
 * DOM Mounting helper
 */
export function mountCommandPalette(containerEl, controller) {
  if (typeof document === 'undefined') return;

  const overlay = document.createElement('div');
  overlay.className = 'command-palette-overlay';
  overlay.style.display = 'none';
  overlay.innerHTML = `
    <div class="command-palette-backdrop"></div>
    <div class="command-palette-dialog" role="dialog" aria-modal="true" aria-label="Command Palette">
      <div class="command-palette-search">
        <span class="search-icon">🔍</span>
        <input type="text" class="command-palette-input" placeholder="Type a command, module, or entity... (Esc to close)" autocomplete="off" spellcheck="false" />
      </div>
      <div class="command-palette-results" role="listbox"></div>
      <div class="command-palette-footer">
        <span><kbd>↑</kbd> <kbd>↓</kbd> Navigate</span>
        <span><kbd>Enter</kbd> Select</span>
        <span><kbd>Esc</kbd> Dismiss</span>
      </div>
    </div>
  `;

  containerEl.appendChild(overlay);

  const inputEl = overlay.querySelector('.command-palette-input');
  const resultsEl = overlay.querySelector('.command-palette-results');
  const backdropEl = overlay.querySelector('.command-palette-backdrop');

  function renderResults() {
    if (!resultsEl) return;
    if (controller.results.length === 0) {
      resultsEl.innerHTML = `<div style="padding:16px; color:var(--text-muted); font-family:var(--font-mono); font-size:12px; text-align:center;">No matching commands or destinations found.</div>`;
      return;
    }

    resultsEl.innerHTML = controller.results
      .map((item, idx) => {
        const isSelected = idx === controller.selectedIndex;
        return `
          <div class="command-item ${isSelected ? 'selected' : ''}" role="option" aria-selected="${isSelected}" data-index="${idx}">
            <div class="command-item-main">
              <span class="command-item-title">${item.icon ? item.icon + ' ' : ''}${item.title}</span>
              <span class="command-item-desc">${item.description || ''}</span>
            </div>
            <span class="badge badge-${item.category === 'navigation' ? 'info' : 'hypothesis'}">${item.category}</span>
          </div>
        `;
      })
      .join('');

    const activeEl = resultsEl.querySelector('.command-item.selected');
    if (activeEl) {
      activeEl.scrollIntoView({ block: 'nearest' });
    }
  }

  // Keydown listener for global Ctrl+K / Cmd+K
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (controller.isOpen) {
        controller.close();
        overlay.style.display = 'none';
      } else {
        controller.open();
        overlay.style.display = 'flex';
        renderResults();
        if (inputEl) {
          inputEl.value = '';
          inputEl.focus();
        }
      }
    } else if (controller.isOpen) {
      if (e.key === 'Escape') {
        e.preventDefault();
        controller.close();
        overlay.style.display = 'none';
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        controller.next();
        renderResults();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        controller.prev();
        renderResults();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        controller.execute();
        overlay.style.display = 'none';
      }
    }
  });

  inputEl?.addEventListener('input', (e) => {
    controller.setQuery(e.target.value);
    renderResults();
  });

  backdropEl?.addEventListener('click', () => {
    controller.close();
    overlay.style.display = 'none';
  });

  resultsEl?.addEventListener('click', (e) => {
    const itemEl = e.target.closest('.command-item');
    if (itemEl) {
      const idx = parseInt(itemEl.dataset.index, 10);
      controller.selectedIndex = idx;
      controller.execute();
      overlay.style.display = 'none';
    }
  });

  return overlay;
}
