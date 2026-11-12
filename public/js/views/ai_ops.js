// public/js/views/ai_ops.js
// EYE OF DHARMA (EOD) — AI Operations & Model Runtime Sandbox View

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <div class="view-title-group">
        <h1><span class="brand-tag font-mono">[AI]</span> AI Operations</h1>
        <div class="view-subtitle font-mono">MULTI-AGENT RUNTIME, PROMPT CITATIONS & MODEL SANDBOX</div>
      </div>
      <div class="view-actions">
        <span class="badge badge-verified font-mono">FALLBACK ENGINE READY</span>
      </div>
    </div>

    <!-- Provider Selection & Architecture -->
    <div class="card-grid">
      <div class="card font-mono">
        <div class="card-header"><span class="card-title">Active Provider</span><span class="badge badge-info">PLUGGABLE</span></div>
        <div class="card-metric" style="color:var(--status-verified); font-size:22px;">Deterministic No-AI</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">100% offline rule-based synthesis engine active when LLM API keys are unconfigured.</div>
      </div>
      <div class="card font-mono">
        <div class="card-header"><span class="card-title">Anti-Hallucination Guard</span><span class="badge badge-verified">ENFORCED</span></div>
        <div class="card-metric" style="color:var(--accent-cyan); font-size:22px;">[EVID-xxxx]</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">All claims verified against cryptographic SHA-256 evidence fingerprints.</div>
      </div>
      <div class="card font-mono">
        <div class="card-header"><span class="card-title">Prompt Injection Defense</span><span class="badge badge-verified">ACTIVE</span></div>
        <div class="card-metric" style="color:var(--accent-gold); font-size:22px;">XML Sandbox</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Untrusted input enclosed in &lt;untrusted_source_data&gt; tags with control character filtering.</div>
      </div>
    </div>

    <!-- Provider Configuration Deck -->
    <div class="card font-mono" style="margin-top:16px;">
      <div class="card-header"><span class="card-title">Supported LLM Provider Endpoints</span></div>
      <div style="font-size:12px; display:flex; flex-direction:column; gap:8px;">
        <div style="padding:8px 12px; background:var(--bg-input); border-radius:2px; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--text-high);">Ollama (Local Private)</strong>
            <div style="color:var(--text-muted); font-size:11px;">Endpoint: <code>http://localhost:11434</code> (Models: llama3.3, mistral, qwen2.5)</div>
          </div>
          <span class="badge badge-neutral">STANDBY</span>
        </div>
        <div style="padding:8px 12px; background:var(--bg-input); border-radius:2px; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--text-high);">Google Gemini API</strong>
            <div style="color:var(--text-muted); font-size:11px;">Models: <code>gemini-2.5-pro</code>, <code>gemini-2.5-flash</code></div>
          </div>
          <span class="badge badge-neutral">ENV VAR: GEMINI_API_KEY</span>
        </div>
        <div style="padding:8px 12px; background:var(--bg-input); border-radius:2px; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--text-high);">Anthropic Claude API</strong>
            <div style="color:var(--text-muted); font-size:11px;">Models: <code>claude-3-7-sonnet</code></div>
          </div>
          <span class="badge badge-neutral">ENV VAR: ANTHROPIC_API_KEY</span>
        </div>
        <div style="padding:8px 12px; background:var(--bg-input); border-radius:2px; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--text-high);">OpenAI GPT-4o API</strong>
            <div style="color:var(--text-muted); font-size:11px;">Models: <code>gpt-4o</code>, <code>o3-mini</code></div>
          </div>
          <span class="badge badge-neutral">ENV VAR: OPENAI_API_KEY</span>
        </div>
      </div>
    </div>
  `;
}
