// public/js/router.js
// EYE OF DHARMA (EOD) — Client-Side SPA Router & View Dispatcher

import { NAVIGATION_MODULES } from './components/navigation_rail.js';

import * as CommandCenterView from './views/command_center.js';
import * as GlobalMonitorView from './views/global_monitor.js';
import * as LiveIntelView from './views/live_intel.js';
import * as CyberThreatsView from './views/cyber_threats.js';
import * as InvestigationsView from './views/investigations.js';
import * as CasesView from './views/cases.js';
import * as EntityGraphView from './views/entity_graph.js';
import * as TimelineModuleView from './views/timeline.js';
import * as AIOpsView from './views/ai_ops.js';
import * as WatchlistsView from './views/watchlists.js';
import * as ReportsView from './views/reports.js';
import * as DataSourcesView from './views/data_sources.js';
import * as AuditLogsView from './views/audit_logs.js';
import * as SettingsView from './views/settings.js';
import * as SystemHealthView from './views/system_health.js';

export const VIEW_HANDLERS = {
  'command-center': CommandCenterView.render,
  'global-monitor': GlobalMonitorView.render,
  'live-intel': LiveIntelView.render,
  'cyber-threats': CyberThreatsView.render,
  'investigations': InvestigationsView.render,
  'cases': CasesView.render,
  'entity-graph': EntityGraphView.render,
  'timeline': TimelineModuleView.render,
  'ai-ops': AIOpsView.render,
  'watchlists': WatchlistsView.render,
  'reports': ReportsView.render,
  'data-sources': DataSourcesView.render,
  'audit-logs': AuditLogsView.render,
  'settings': SettingsView.render,
  'system-health': SystemHealthView.render
};

export class Router {
  constructor(mainContainerId = 'main-content') {
    this.mainContainerId = mainContainerId;
    this.mainContainer = null;
    this.currentPath = '';
    this.modules = NAVIGATION_MODULES;
  }

  init() {
    if (typeof document === 'undefined') return;
    this.mainContainer = document.getElementById(this.mainContainerId);
    if (!this.mainContainer) return;

    // Intercept client-side link navigation
    document.addEventListener('click', (e) => {
      const target = e.target.closest('a[data-route]');
      if (target) {
        e.preventDefault();
        const route = target.getAttribute('data-route') || '/command-center';
        this.navigate(route);
      }
    });

    // Handle browser back/forward buttons
    window.addEventListener('popstate', () => {
      this.resolve(window.location.pathname);
    });

    // Initial route resolution
    const initialPath = window.location.pathname === '/' ? '/command-center' : window.location.pathname;
    this.navigate(initialPath, true);
  }

  navigate(path, replace = false) {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    if (replace) {
      window.history.replaceState({ path: normalizedPath }, '', normalizedPath);
    } else {
      window.history.pushState({ path: normalizedPath }, '', normalizedPath);
    }
    this.resolve(normalizedPath);
  }

  resolve(path) {
    if (!this.mainContainer) return;

    let matchedModule = this.modules.find((m) => m.path === path || path.startsWith(`${m.path}/`));

    // Default fallback to command-center if route not found
    if (!matchedModule) {
      matchedModule = this.modules[0];
      window.history.replaceState({ path: matchedModule.path }, '', matchedModule.path);
    }

    this.currentPath = matchedModule.path;

    // Update Navigation Rail active indicators
    this.updateRailActiveState(matchedModule.path);

    // Update document title and top breadcrumb
    document.title = `EYE OF DHARMA // ${matchedModule.name.toUpperCase()}`;
    const breadcrumbEl = document.getElementById('active-module-title');
    if (breadcrumbEl) {
      breadcrumbEl.textContent = matchedModule.name.toUpperCase();
    }

    // Clear and render the active view container
    this.mainContainer.innerHTML = '';
    const viewWrapper = document.createElement('div');
    viewWrapper.className = 'view-container';
    viewWrapper.setAttribute('data-module-id', matchedModule.id);
    this.mainContainer.appendChild(viewWrapper);

    const renderFn = VIEW_HANDLERS[matchedModule.id];
    if (typeof renderFn === 'function') {
      renderFn(viewWrapper);
    }

    // Dispatch custom event for views with active canvases (MapLibre, Radar, Cytoscape)
    window.dispatchEvent(
      new CustomEvent('eod:route-changed', {
        detail: { moduleId: matchedModule.id, path: matchedModule.path }
      })
    );
  }

  updateRailActiveState(activePath) {
    const links = document.querySelectorAll('.nav-link');
    links.forEach((link) => {
      const route = link.getAttribute('data-route');
      if (route === activePath || (activePath !== '/' && activePath.startsWith(`${route}/`))) {
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
      } else {
        link.classList.remove('active');
        link.removeAttribute('aria-current');
      }
    });
  }
}
