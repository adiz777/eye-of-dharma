// public/js/views/cases.js
// EYE OF DHARMA (EOD) — Case Management & Investigation Workspace View

import { mountCaseWorkspace } from '../components/case_workspace.js';

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[CASES]</span> Case Management</h1>
        <div class="view-subtitle font-mono">OPERATIONAL DOSSIERS, EVIDENCE LEDGER & CHAIN OF CUSTODY</div>
      </div>
      <div class="view-actions">
        <button class="btn btn-primary" id="btn-create-case" style="font-size:11px;">+ New Case Dossier</button>
      </div>
    </div>

    <!-- Active Case Workspace Mount -->
    <div id="case-workspace-mount" style="margin-top:8px;"></div>
  `;

  const mountEl = container.querySelector('#case-workspace-mount');
  if (mountEl) {
    mountCaseWorkspace(mountEl, 'case-00000000-0000-0000-0000-000000000001');
  }

  container.querySelector('#btn-create-case')?.addEventListener('click', () => {
    const title = prompt('Enter Case Title:', 'Operation Nordic Shield');
    if (!title) return;
    const desc = prompt('Enter Case Description:', 'Investigation into anomalous telemetry on Baltic interconnect.');
    if (!desc) return;

    fetch('/api/v1/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        description: desc,
        priority: 'HIGH',
        tlp: 'TLP:AMBER',
        classification: 'UNCLASSIFIED',
        lead_analyst: 'DHARMA Coordinator'
      })
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.success && data.data?.id) {
          alert(`Created case: ${data.data.title} (${data.data.id})`);
          if (mountEl) {
            mountEl.innerHTML = '';
            mountCaseWorkspace(mountEl, data.data.id);
          }
        } else {
          alert('Failed to create case');
        }
      })
      .catch(() => alert('Network error creating case'));
  });
}
