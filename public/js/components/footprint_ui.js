// public/js/components/footprint_ui.js
// Digital Footprint Investigator UI with Passive Confirmation & Negative vs Failure Distinction

export const FOOTPRINT_STATUS = {
  IDLE: 'IDLE',
  CONFIRMING: 'CONFIRMING',
  QUERYING: 'QUERYING',
  NEGATIVE_RESULT: 'NEGATIVE_RESULT', // 200 OK, found: false
  UPSTREAM_FAILURE: 'UPSTREAM_FAILURE', // 400/500/504
  SUCCESS: 'SUCCESS' // 200 OK, found: true
};

/**
 * Validates query inputs before opening confirmation modal
 */
export function validateFootprintInput(queryType, target) {
  if (!target || !target.trim()) {
    return { valid: false, error: 'Target identifier is required.' };
  }
  const clean = target.trim();

  switch (queryType) {
    case 'DOMAIN': {
      const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
      if (!domainRegex.test(clean)) {
        return { valid: false, error: 'Invalid domain name format (e.g. example.com).' };
      }
      break;
    }
    case 'IP': {
      // IPv4 syntax check
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
      if (!ipv4Regex.test(clean) && !ipv6Regex.test(clean)) {
        return { valid: false, error: 'Invalid IPv4 or IPv6 address format.' };
      }
      if (ipv4Regex.test(clean)) {
        const octets = clean.split('.').map(Number);
        if (octets.some((o) => o < 0 || o > 255)) {
          return { valid: false, error: 'Invalid IPv4 octet value.' };
        }
      }
      break;
    }
    case 'EMAIL': {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(clean)) {
        return { valid: false, error: 'Invalid email address format.' };
      }
      break;
    }
    case 'USERNAME': {
      if (clean.length < 2 || clean.length > 64) {
        return { valid: false, error: 'Username must be between 2 and 64 characters.' };
      }
      break;
    }
    case 'CERTIFICATE': {
      if (clean.length < 3) {
        return { valid: false, error: 'Certificate common name or fingerprint must be at least 3 characters.' };
      }
      break;
    }
    default:
      return { valid: false, error: `Unsupported query type: ${queryType}` };
  }

  return { valid: true, target: clean };
}

/**
 * Classifies footprint API responses into strict UI states
 */
export function classifyFootprintResponse(statusCode, data, error) {
  if (statusCode === 200 && data && data.success) {
    if (data.found === false || !data.records || data.records.length === 0) {
      return {
        status: FOOTPRINT_STATUS.NEGATIVE_RESULT,
        badgeText: 'NO RECORDS FOUND - 200 OK',
        badgeClass: 'badge-neutral',
        explanation: 'Target was queried across authoritative resolvers and public registries. Zero matching records were found.',
        canRetry: false,
        canAttach: false,
        records: []
      };
    }
    return {
      status: FOOTPRINT_STATUS.SUCCESS,
      badgeText: 'RECORDS OBSERVED - 200 OK',
      badgeClass: 'badge-success',
      explanation: `Successfully observed ${data.records.length} passive intelligence records.`,
      canRetry: false,
      canAttach: true,
      records: data.records,
      evidenceId: data.evidence_id
    };
  }

  const errCode = error?.code || data?.error?.code || statusCode;
  const errMsg = error?.message || data?.error?.message || 'Upstream query failed or timed out.';
  const codeLabel = statusCode ? `${statusCode}${errCode && errCode !== statusCode ? ` (${errCode})` : ''}` : String(errCode);
  return {
    status: FOOTPRINT_STATUS.UPSTREAM_FAILURE,
    badgeText: `UPSTREAM QUERY FAILED - ${codeLabel}`,
    badgeClass: 'badge-danger',
    explanation: errMsg,
    canRetry: true,
    canAttach: false,
    records: []
  };
}

/**
 * Returns planned query descriptions for upfront user confirmation
 */
export function getPlannedQueriesForType(queryType, target) {
  switch (queryType) {
    case 'DOMAIN':
      return [
        { source: 'System DNS Resolvers', desc: `Query A, AAAA, MX, TXT, NS, SOA records for '${target}'` },
        { source: 'ICANN RDAP Bootstrap', desc: `Query domain registry allocation & registrar for '${target}'` },
        { source: 'crt.sh Certificate Logs', desc: `Query Certificate Transparency append-only log for '${target}'` }
      ];
    case 'IP':
      return [
        { source: 'System DNS PTR', desc: `Reverse PTR hostname resolution for IP '${target}'` },
        { source: 'Regional RDAP Registries', desc: `Query ARIN/RIPE/APNIC IP block allocation for '${target}'` }
      ];
    case 'CERTIFICATE':
      return [
        { source: 'crt.sh Transparency DB', desc: `Search public X.509 certificate logs for '${target}'` }
      ];
    case 'EMAIL':
    case 'USERNAME':
      return [
        { source: 'Passive OSINT Index', desc: `Cross-reference known public breach & persona indices for '${target}'` }
      ];
    default:
      return [];
  }
}

/**
 * Footprint UI State Controller
 */
export class FootprintController {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || '/api/v1';
    this.status = FOOTPRINT_STATUS.IDLE;
    this.currentQuery = null;
    this.result = null;
    this.onStateChange = options.onStateChange || (() => {});
  }

  prepareQuery(queryType, target, caseId = null) {
    const val = validateFootprintInput(queryType, target);
    if (!val.valid) {
      return val;
    }

    this.currentQuery = {
      queryType,
      target: val.target,
      caseId,
      plannedQueries: getPlannedQueriesForType(queryType, val.target)
    };
    this.status = FOOTPRINT_STATUS.CONFIRMING;
    this.onStateChange();
    return { valid: true, query: this.currentQuery };
  }

  cancelConfirmation() {
    this.status = FOOTPRINT_STATUS.IDLE;
    this.onStateChange();
  }

  async executeConfirmedQuery() {
    if (!this.currentQuery) return;

    this.status = FOOTPRINT_STATUS.QUERYING;
    this.onStateChange();

    try {
      const res = await fetch(`${this.baseUrl}/investigate/footprint`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query_type: this.currentQuery.queryType,
          target: this.currentQuery.target,
          confirm_passive: true,
          case_id: this.currentQuery.caseId || null
        })
      });

      const data = await res.json();
      this.result = classifyFootprintResponse(res.status, data, data?.error);
      this.status = this.result.status;
      this.onStateChange();
    } catch (err) {
      this.result = classifyFootprintResponse(500, null, {
        code: 'NETWORK_ERROR',
        message: err.message || String(err)
      });
      this.status = FOOTPRINT_STATUS.UPSTREAM_FAILURE;
      this.onStateChange();
    }
  }
}

/**
 * DOM Mounting helper
 */
export function mountFootprintUI(containerEl, options = {}) {
  if (typeof document === 'undefined') return;

  const controller = new FootprintController(options);
  const wrapper = document.createElement('div');
  wrapper.className = 'footprint-shell';

  function render() {
    wrapper.innerHTML = `
      <!-- Persistent Passive Assurance Banner -->
      <div class="footprint-banner">
        <div style="display:flex; align-items:center; gap:10px;">
          <span style="font-size:16px;">🛡️</span>
          <div>
            <div style="font-weight:700; color:var(--accent-cyan); font-size:12px;">NON-INTRUSIVE PASSIVE RECONNAISSANCE GUARANTEE</div>
            <div style="color:var(--text-muted); font-size:11px;">Zero active port scans, zero packets sent to target infrastructure. All queries directed to public registries (DNS, RDAP, crt.sh).</div>
          </div>
        </div>
        <span class="badge badge-verified">PASSIVE MODE ENFORCED</span>
      </div>

      <!-- Target Input Deck -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Target Reconnaissance Parameters</span>
          <span class="font-mono text-muted" style="font-size:11px;">STEP 1: DISCLOSE SCOPE</span>
        </div>
        <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end;">
          <div style="display:flex; flex-direction:column; gap:4px;">
            <label style="font-size:11px; color:var(--text-muted);">TARGET TYPE</label>
            <select id="fp-type-select" class="input-control font-mono" style="min-width:140px;">
              <option value="DOMAIN">DOMAIN</option>
              <option value="IP">IP ADDRESS</option>
              <option value="EMAIL">EMAIL</option>
              <option value="USERNAME">USERNAME</option>
              <option value="CERTIFICATE">CERTIFICATE</option>
            </select>
          </div>
          <div style="flex:1; min-width:240px; display:flex; flex-direction:column; gap:4px;">
            <label style="font-size:11px; color:var(--text-muted);">TARGET IDENTIFIER</label>
            <input type="text" id="fp-target-input" class="input-control" placeholder="e.g. example.com or 198.51.100.1..." autocomplete="off" />
          </div>
          <button id="fp-plan-btn" class="btn btn-primary" style="height:36px;">
            Plan Passive Recon
          </button>
        </div>
        <div id="fp-error-msg" style="color:var(--status-critical); font-size:11px; margin-top:8px; display:none;"></div>
      </div>

      <!-- Result Card -->
      ${renderResultSection()}

      <!-- Upfront Confirmation Modal -->
      ${renderModalSection()}
    `;

    bindEvents();
  }

  function renderResultSection() {
    if (!controller.result) return '';

    const res = controller.result;
    return `
      <div class="card font-mono" style="margin-top:16px;">
        <div class="card-header">
          <div style="display:flex; align-items:center; gap:10px;">
            <span class="badge ${res.badgeClass}">${res.badgeText}</span>
            <span style="font-size:12px; color:var(--text-muted);">${res.explanation}</span>
            ${res.evidenceId ? `<span class="badge badge-verified" style="margin-left:8px;">LINKED: ${res.evidenceId}</span>` : ''}
          </div>
          ${res.canRetry ? `<button id="fp-retry-btn" class="btn btn-secondary" style="font-size:11px;">Retry Query</button>` : ''}
        </div>

        ${
          res.records && res.records.length > 0
            ? `
          <table class="data-table" style="margin-top:10px;">
            <thead>
              <tr><th>TYPE</th><th>RECORD / VALUE</th><th>SOURCE</th></tr>
            </thead>
            <tbody>
              ${res.records
                .map(
                  (r) => `
                <tr>
                  <td><span class="badge badge-info">${r.type || 'RECORD'}</span></td>
                  <td style="color:var(--text-high);">${r.value || JSON.stringify(r)}</td>
                  <td style="color:var(--text-muted);">${r.source || 'PUBLIC_OSINT'}</td>
                </tr>
              `
                )
                .join('')}
            </tbody>
          </table>
        `
            : res.status === FOOTPRINT_STATUS.NEGATIVE_RESULT
            ? `
          <div style="padding:24px; text-align:center; background:var(--bg-input); border-radius:2px; border:1px solid var(--border-subtle); margin-top:10px;">
            <div style="font-size:14px; color:var(--text-muted); margin-bottom:6px;">[ ZERO OBSERVABLE RECORDS ]</div>
            <div style="font-size:11px; color:var(--text-disabled);">Target is not present in queried DNS zones, RDAP registry blocks, or Certificate Transparency append-only logs.</div>
          </div>
        `
            : ''
        }
      </div>
    `;
  }

  function renderModalSection() {
    if (controller.status !== FOOTPRINT_STATUS.CONFIRMING || !controller.currentQuery) {
      return '';
    }

    const q = controller.currentQuery;
    return `
      <div class="modal-overlay">
        <div class="modal-dialog">
          <div class="modal-header">
            <span style="font-weight:700; color:var(--accent-cyan); font-size:13px;">[CONFIRM PLANNED PASSIVE QUERIES]</span>
            <button id="modal-close-btn" style="background:transparent; border:none; color:var(--text-muted); cursor:pointer; font-size:16px;">✕</button>
          </div>
          <div class="modal-body">
            <div style="margin-bottom:12px;">
              <span style="color:var(--text-muted); font-size:11px;">TARGET:</span>
              <strong style="color:var(--text-high); font-size:14px; margin-left:6px;">${q.target}</strong>
              <span class="badge badge-info" style="margin-left:8px;">${q.queryType}</span>
            </div>
            <div style="font-size:11px; color:var(--text-muted); margin-bottom:12px;">
              The following passive lookups will be dispatched. No direct contact with the target will occur:
            </div>
            <ul style="list-style:none; display:flex; flex-direction:column; gap:8px; margin-bottom:16px;">
              ${q.plannedQueries
                .map(
                  (pq) => `
                <li style="padding:8px 10px; background:var(--bg-input); border-left:2px solid var(--accent-cyan); font-family:var(--font-mono); font-size:11px;">
                  <div style="font-weight:600; color:var(--text-high);">${pq.source}</div>
                  <div style="color:var(--text-muted); font-size:10px;">${pq.desc}</div>
                </li>
              `
                )
                .join('')}
            </ul>
            <div style="font-size:11px; color:var(--accent-gold); background:rgba(212,175,55,0.1); padding:8px 10px; border-radius:2px; border:1px solid rgba(212,175,55,0.3);">
              ⚠️ Passive-only guarantee: <code>confirm_passive: true</code> is sent to the backend. Inquiries are permanently logged in the audit ledger.
            </div>
          </div>
          <div class="modal-footer">
            <button id="modal-cancel-btn" class="btn btn-secondary">Cancel</button>
            <button id="modal-confirm-btn" class="btn btn-primary">Confirm & Execute Lookups</button>
          </div>
        </div>
      </div>
    `;
  }

  function bindEvents() {
    const planBtn = wrapper.querySelector('#fp-plan-btn');
    const typeSelect = wrapper.querySelector('#fp-type-select');
    const targetInput = wrapper.querySelector('#fp-target-input');
    const errorMsg = wrapper.querySelector('#fp-error-msg');

    planBtn?.addEventListener('click', () => {
      const qType = typeSelect?.value || 'DOMAIN';
      const target = targetInput?.value || '';
      const val = controller.prepareQuery(qType, target);
      if (!val.valid) {
        if (errorMsg) {
          errorMsg.textContent = val.error;
          errorMsg.style.display = 'block';
        }
      } else {
        if (errorMsg) errorMsg.style.display = 'none';
      }
    });

    wrapper.querySelector('#modal-close-btn')?.addEventListener('click', () => controller.cancelConfirmation());
    wrapper.querySelector('#modal-cancel-btn')?.addEventListener('click', () => controller.cancelConfirmation());
    wrapper.querySelector('#modal-confirm-btn')?.addEventListener('click', () => controller.executeConfirmedQuery());
    wrapper.querySelector('#fp-retry-btn')?.addEventListener('click', () => controller.executeConfirmedQuery());
  }

  controller.onStateChange = () => render();
  containerEl.appendChild(wrapper);
  render();

  return controller;
}
