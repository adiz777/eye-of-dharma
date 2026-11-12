// public/js/views/reports.js
// EYE OF DHARMA (EOD) — Grounded Intelligence Reports & Multi-Format Export View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[REPRT]</span> Reports</h1>
        <div class="view-subtitle font-mono">GROUNDED DOSSIER GENERATOR & MULTI-FORMAT EXPORT ENGINE</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-verified font-mono">STIX 2.1 COMPLIANT</span>
      </div>
    </div>

    <div class="card-grid">
      <!-- HTML Dossier Export -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">Standalone Dark HTML</span>
          <span class="badge badge-info">BROWSER NATIVE</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin:8px 0 16px 0;">
          Self-contained high-density dark operations dossier with embedded CSS, cryptographic evidence pills, and print stylesheet.
        </p>
        <button class="btn btn-primary btn-export" data-format="html" style="margin-top:auto;">
          Download HTML Dossier
        </button>
      </div>

      <!-- PDF Export -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">Executive PDF Brief</span>
          <span class="badge badge-gold">PRINT-READY</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin:8px 0 16px 0;">
          Paginated tactical intelligence brief with executive summary, methodology, evidence ledger, limitations, and attribution.
        </p>
        <button class="btn btn-primary btn-export" data-format="pdf" style="margin-top:auto;">
          Generate PDF Brief
        </button>
      </div>

      <!-- STIX 2.1 JSON Export -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">STIX 2.1 JSON Bundle</span>
          <span class="badge badge-verified">MACHINE READABLE</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin:8px 0 16px 0;">
          Standardized cyber threat intelligence bundle containing indicators, observed entities, identity nodes, and relationship edges.
        </p>
        <button class="btn btn-secondary btn-export" data-format="json" style="margin-top:auto;">
          Export STIX 2.1 JSON
        </button>
      </div>

      <!-- RFC 4180 CSV Export -->
      <div class="card font-mono">
        <div class="card-header">
          <span class="card-title">RFC 4180 CSV Ledger</span>
          <span class="badge badge-neutral">TABULAR</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin:8px 0 16px 0;">
          Raw evidence ledger export with source URLs, timestamps, verification confidence, and immutable SHA-256 fingerprints.
        </p>
        <button class="btn btn-secondary btn-export" data-format="csv" style="margin-top:auto;">
          Export CSV Ledger
        </button>
      </div>
    </div>
  `;

  container.querySelectorAll('.btn-export').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const format = btn.getAttribute('data-format');
      const caseId = 'case-00000000-0000-0000-0000-000000000001';

      try {
        const res = await fetch(`/api/v1/cases/${caseId}/export`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ format })
        });

        if (format === 'html' || format === 'csv' || format === 'json') {
          const text = await res.text();
          const blob = new Blob([text], {
            type: format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/html'
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `EOD-REPORT-${caseId.slice(0, 8)}.${format}`;
          a.click();
          URL.revokeObjectURL(url);
        } else {
          alert(`[✓] PDF report generated for Case ${caseId.slice(0, 8)}.`);
        }
      } catch (err) {
        alert(`Export failed: ${err.message || String(err)}`);
      }
    });
  });
}
