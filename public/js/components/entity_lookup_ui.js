// public/js/components/entity_lookup_ui.js
// Public-source lookup panel for people (public figures), organisations and usernames.
import { esc } from '../escape.js';

const STATUS = {
  found: ['badge-success', 'FOUND'],
  not_found: ['badge-neutral', 'NO MATCH'],
  error: ['badge-danger', 'LOOKUP FAILED'],
  unsupported: ['badge-warning', 'KEY REQUIRED']
};

export function mountEntityLookup(el) {
  el.innerHTML = `
    <div class="card font-mono">
      <div class="card-header"><span class="card-title">Public-Source Entity Lookup</span><span class="badge badge-info">PASSIVE</span></div>
      <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px;">
        Queries public registries and profile APIs only. People: Wikidata (public figures) and sanctions/PEP lists. Organisations: Wikidata, GLEIF, SEC EDGAR, UK Companies House*, OpenSanctions*. Usernames: GitHub, GitLab, Hacker News.
        Your input is sent to those providers. Matches are leads, not proof of identity. *needs a free API key in server env.
      </div>
      <form id="ent-form" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
        <select id="ent-type" class="btn btn-secondary" aria-label="Lookup type">
          <option value="ORGANIZATION">ORGANISATION</option>
          <option value="PERSON">PERSON (public figure)</option>
          <option value="USERNAME">USERNAME</option>
        </select>
        <input id="ent-target" class="btn btn-secondary" style="flex:1; min-width:200px; text-align:left;" placeholder="Name or handle" maxlength="120" required aria-label="Target" />
        <button class="btn btn-primary" type="submit">RUN LOOKUP</button>
        <label style="font-size:11px; width:100%;"><input type="checkbox" id="ent-ok" required />
          I confirm this lookup is lawful, proportionate and for a public figure, organisation or subject I am authorised to research.</label>
      </form>
      <div id="ent-out" style="margin-top:12px;" aria-live="polite"></div>
    </div>`;

  const out = el.querySelector('#ent-out');
  el.querySelector('#ent-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = {
      query_type: el.querySelector('#ent-type').value,
      target: el.querySelector('#ent-target').value.trim(),
      confirm_passive: true,
      confirm_lawful_purpose: el.querySelector('#ent-ok').checked
    };
    out.textContent = 'Querying public sources…';
    try {
      const res = await fetch('/api/v1/investigate/entity', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!data.success) {
        out.innerHTML = `<span style="color:var(--status-critical)">${esc(data.error?.message || 'Request failed')}</span>`;
        return;
      }
      out.innerHTML = data.sources.map((s) => {
        const [cls, label] = STATUS[s.status] || STATUS.error;
        const rows = s.records.map((r) => {
          const safe = /^https:\/\//.test(r.url || '');
          const name = safe ? `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.label)}</a>` : esc(r.label);
          const detail = r.details ? ' · ' + esc(Object.entries(r.details).filter(([, v]) => v != null && typeof v !== 'object').map(([k, v]) => `${k}: ${v}`).join(' · ')) : '';
          return `<div style="padding:2px 0 2px 12px; font-size:11px;">${name}<span style="color:var(--text-muted)">${detail}</span></div>`;
        }).join('');
        return `<div style="margin-bottom:8px;"><span class="badge ${cls}">${label}</span> <strong style="font-size:12px;">${esc(s.sourceName)}</strong>${s.note && s.status !== 'found' ? ` <span style="color:var(--text-muted); font-size:10px;">${esc(s.note)}</span>` : ''}${rows}</div>`;
      }).join('') + `<div style="font-size:10px; color:var(--text-muted);">${esc(data.caveat)}</div>`;
    } catch {
      out.innerHTML = '<span style="color:var(--status-critical)">API unreachable.</span>';
    }
  });
}
