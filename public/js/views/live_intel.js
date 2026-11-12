// public/js/views/live_intel.js
// EYE OF DHARMA (EOD) — Live Intelligence Ingestion View
import { esc } from '../escape.js';

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[INTEL]</span> Live Intelligence</h1>
        <div class="view-subtitle font-mono">NORMALIZED PUBLIC OSINT FEED STREAM & INGESTION TELEMETRY</div>
      </div>
      <div class="view-actions">
        <button class="btn btn-primary" id="btn-refresh-feeds" style="font-size:11px;">
          🔄 Ingest Public Feeds
        </button>
      </div>
    </div>

    <!-- Filter Bar -->
    <div class="card font-mono" style="padding:10px 14px;">
      <div style="display:flex; align-items:center; gap:16px; flex-wrap:wrap; font-size:11px;">
        <div style="display:flex; align-items:center; gap:6px;">
          <span style="color:var(--text-muted)">CATEGORY:</span>
          <select id="feed-cat-filter" class="input-control" style="padding:2px 6px; font-size:11px;">
            <option value="ALL">ALL CATEGORIES</option>
            <option value="EARTHQUAKE">EARTHQUAKE (USGS)</option>
            <option value="HAZARD">HAZARD (EONET)</option>
            <option value="VULNERABILITY">VULNERABILITY (CISA KEV)</option>
            <option value="ADVISORY">ADVISORY (CISA)</option>
            <option value="CERTIFICATE">CERTIFICATE (CRT.SH)</option>
            <option value="NEWS">NEWS (RSS)</option>
          </select>
        </div>
        <div style="display:flex; align-items:center; gap:6px;">
          <span style="color:var(--text-muted)">SEVERITY:</span>
          <select id="feed-sev-filter" class="input-control" style="padding:2px 6px; font-size:11px;">
            <option value="ALL">ALL SEVERITIES</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
        <div style="margin-left:auto; color:var(--text-muted);" id="feed-count-hud">
          SHOWING 0 RECORDS
        </div>
      </div>
    </div>

    <!-- Live Feeds Table -->
    <div class="card font-mono" style="margin-top:12px; flex:1;">
      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>TIMESTAMP</th>
              <th>SOURCE</th>
              <th>CATEGORY</th>
              <th>SEV</th>
              <th>TITLE</th>
              <th>ATTRIBUTION</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody id="feeds-tbody">
            <tr>
              <td colspan="7" style="text-align:center; padding:24px; color:var(--text-muted);">
                Streaming verified public OSINT records...
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  let currentItems = [];

  async function loadFeeds() {
    const cat = container.querySelector('#feed-cat-filter')?.value || 'ALL';
    const sev = container.querySelector('#feed-sev-filter')?.value || 'ALL';

    let url = '/api/v1/feeds?limit=100';
    if (cat !== 'ALL') url += `&category=${cat}`;

    try {
      const res = await fetch(url);
      const data = await res.json();
      if (data && Array.isArray(data.items)) {
        currentItems = data.items;
        if (sev !== 'ALL') {
          currentItems = currentItems.filter((i) => i.severity === sev);
        }
        renderTableRows(currentItems);
      }
    } catch (err) {
      console.error('[LiveIntel] Failed to load feeds:', err);
    }
  }

  function renderTableRows(items) {
    const tbody = container.querySelector('#feeds-tbody');
    const hud = container.querySelector('#feed-count-hud');
    if (hud) hud.textContent = `SHOWING ${items.length} RECORDS`;
    if (!tbody) return;

    if (items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-muted);">No feed records match current filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = items
      .map((item) => {
        const sevClass =
          item.severity === 'CRITICAL' ? 'badge-critical' : item.severity === 'HIGH' ? 'badge-inferred' : 'badge-info';
        const time = item.published_at ? item.published_at.substring(11, 19) + 'Z' : 'N/A';

        return `
        <tr>
          <td style="color:var(--text-muted);">${time}</td>
          <td><span class="badge font-mono" style="color:var(--accent-cyan);">${esc(item.feed_name || 'FEED')}</span></td>
          <td><span class="badge badge-info">${item.category}</span></td>
          <td><span class="badge ${sevClass}">${item.severity}</span></td>
          <td style="color:var(--text-high); font-weight:600; max-width:400px; overflow:hidden; text-overflow:ellipsis;">${esc(item.title)}</td>
          <td><span style="color:var(--status-verified);">● Observed</span></td>
          <td>
            <button class="btn btn-secondary btn-attach-feed" data-id="${item.id}" style="padding:2px 8px; font-size:10px;">
              + ATTACH
            </button>
          </td>
        </tr>
      `;
      })
      .join('');

    tbody.querySelectorAll('.btn-attach-feed').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const item = items.find((x) => x.id === id);
        if (!item) return;

        try {
          const res = await fetch('/api/v1/cases/case-00000000-0000-0000-0000-000000000001/evidence', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              source_url: item.source_url || `https://eod.internal/feed/${item.id}`,
              source_type: item.category === 'EARTHQUAKE' ? 'USGS_EARTHQUAKE' : 'RSS_FEED',
              source_title: item.title,
              raw_content: JSON.stringify(item),
              verification_status: 'Observed',
              confidence_score: 0.9,
              notes: `Attached from Live Intelligence feed (${item.category})`
            })
          });
          const resData = await res.json();
          if (resData.success) {
            btn.textContent = '✓ ATTACHED';
            btn.style.color = 'var(--status-verified)';
          }
        } catch {
          alert('Failed to attach evidence');
        }
      });
    });
  }

  container.querySelector('#feed-cat-filter')?.addEventListener('change', () => loadFeeds());
  container.querySelector('#feed-sev-filter')?.addEventListener('change', () => loadFeeds());
  container.querySelector('#btn-refresh-feeds')?.addEventListener('click', async () => {
    try {
      await fetch('/api/v1/feeds/refresh', { method: 'POST' });
      await loadFeeds();
    } catch {
      await loadFeeds();
    }
  });

  loadFeeds();
}
