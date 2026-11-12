// public/js/components/terminal_console.js
// Allowlisted HUD Terminal with Strict Client & Server Metacharacter Blocking

export const ALLOWED_COMMANDS = [
  'help',
  'status',
  'sources',
  'cases list',
  'case show',
  'threats recent',
  'system health',
  'clear'
];

export const SHELL_METACHARACTER_REGEX = /[;&|`$><()\\!{}]/;

/**
 * Strictly parses and validates terminal commands against injection and allowlists
 */
export function parseTerminalCommand(rawInput) {
  if (typeof rawInput !== 'string') {
    return { valid: false, error: 'Command must be a string' };
  }

  const trimmed = rawInput.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: 'Empty command' };
  }

  if (trimmed.length > 256) {
    return { valid: false, error: 'Command exceeds maximum length of 256 characters' };
  }

  // Shell metacharacter injection blocking
  if (SHELL_METACHARACTER_REGEX.test(trimmed)) {
    return {
      valid: false,
      error: 'Security Warning: Illegal characters detected. Shell metacharacters are strictly prohibited.'
    };
  }

  const parts = trimmed.split(/\s+/);
  const verb = parts[0].toLowerCase();
  const arg1 = (parts[1] || '').toLowerCase();
  const arg2 = parts[2];

  // Specific allowlist validation
  if (verb === 'help') {
    return { valid: true, verb: 'help', clientOnly: false };
  }

  if (verb === 'clear') {
    return { valid: true, verb: 'clear', clientOnly: true };
  }

  if (verb === 'status') {
    return { valid: true, verb: 'status', clientOnly: false };
  }

  if (verb === 'sources') {
    return { valid: true, verb: 'sources', clientOnly: false };
  }

  if (verb === 'cases') {
    if (arg1 === 'list' || !arg1) {
      return { valid: true, verb: 'cases', subCommand: 'list', clientOnly: false };
    }
    return { valid: false, error: "Unknown subcommand for 'cases'. Allowlisted usage: 'cases list'" };
  }

  if (verb === 'case') {
    if (arg1 === 'show' && arg2) {
      return { valid: true, verb: 'case', subCommand: 'show', targetId: arg2, clientOnly: false };
    }
    return { valid: false, error: "Invalid usage of 'case'. Allowlisted usage: 'case show <case_id>'" };
  }

  if (verb === 'threats') {
    if (arg1 === 'recent' || !arg1) {
      return { valid: true, verb: 'threats', subCommand: 'recent', clientOnly: false };
    }
    return { valid: false, error: "Unknown subcommand for 'threats'. Allowlisted usage: 'threats recent'" };
  }

  if (verb === 'system') {
    if (arg1 === 'health' || !arg1) {
      return { valid: true, verb: 'system', subCommand: 'health', clientOnly: false };
    }
    return { valid: false, error: "Unknown subcommand for 'system'. Allowlisted usage: 'system health'" };
  }

  return {
    valid: false,
    error: `Command '${verb}' is not recognized or not permitted. Type 'help' for allowlisted operations.`
  };
}

/**
 * Terminal History Manager
 */
export class TerminalHistory {
  constructor(maxSize = 50) {
    this.maxSize = maxSize;
    this.history = [];
    this.index = -1;
    this.savedDraft = '';
  }

  push(command) {
    if (!command || !command.trim()) return;
    const clean = command.trim();
    // Do not repeat identical previous command
    if (this.history[this.history.length - 1] === clean) {
      this.index = -1;
      return;
    }
    this.history.push(clean);
    if (this.history.length > this.maxSize) {
      this.history.shift();
    }
    this.index = -1;
  }

  navigateUp(currentDraft = '') {
    if (this.history.length === 0) return currentDraft;
    if (this.index === -1) {
      this.savedDraft = currentDraft;
      this.index = this.history.length - 1;
    } else if (this.index > 0) {
      this.index--;
    }
    return this.history[this.index];
  }

  navigateDown() {
    if (this.history.length === 0 || this.index === -1) return this.savedDraft;
    if (this.index < this.history.length - 1) {
      this.index++;
      return this.history[this.index];
    } else {
      this.index = -1;
      return this.savedDraft;
    }
  }
}

/**
 * Terminal Controller for Client-Server Interaction
 */
export class TerminalController {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || '/api/v1';
    this.history = new TerminalHistory();
    this.lines = [
      { id: 'init-1', type: 'output', text: 'EYE OF DHARMA // TACTICAL INTELLIGENCE TERMINAL v1.0.0' },
      { id: 'init-2', type: 'output', text: "Type 'help' for allowlisted system operations." }
    ];
    this.isDocked = options.isDocked ?? true;
    this.onOutput = options.onOutput || (() => {});
  }

  async execute(rawInput) {
    const trimmed = rawInput.trim();
    if (!trimmed) return;

    this.history.push(trimmed);
    this.appendLine({ type: 'input', text: `EOD-OSINT:~$ ${trimmed}` });

    const parseResult = parseTerminalCommand(trimmed);
    if (!parseResult.valid) {
      this.appendLine({ type: 'error', text: parseResult.error });
      return;
    }

    if (parseResult.clientOnly && parseResult.verb === 'clear') {
      this.lines = [];
      this.onOutput();
      return;
    }

    try {
      const res = await fetch(`${this.baseUrl}/terminal/exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: trimmed })
      });
      const data = await res.json();
      if (data && data.output) {
        this.appendLine({ type: 'output', text: data.output, executionMs: data.execution_ms });
      } else if (data && data.error) {
        this.appendLine({ type: 'error', text: data.error.message || 'Execution error' });
      } else {
        this.appendLine({ type: 'error', text: 'Terminal response format error.' });
      }
    } catch (err) {
      this.appendLine({ type: 'error', text: `Network error: ${err.message || String(err)}` });
    }
  }

  appendLine(line) {
    this.lines.push({
      id: Date.now() + Math.random(),
      timestamp: new Date().toISOString(),
      ...line
    });
    this.onOutput();
  }
}

/**
 * DOM Mounting helper
 */
export function mountTerminalConsole(containerEl, controller = new TerminalController()) {
  if (typeof document === 'undefined') return controller;

  const shell = document.createElement('div');
  shell.className = 'terminal-hud';
  shell.innerHTML = `
    <div class="terminal-header">
      <div style="display:flex; align-items:center; gap:8px;">
        <span class="status-dot pulsing"></span>
        <span style="color:var(--accent-cyan); font-weight:700;">ALLOWLISTED TERMINAL HUD</span>
      </div>
      <div style="display:flex; align-items:center; gap:12px; font-size:10px;">
        <span>MODE: STRICT_ALLOWLIST</span>
        <button id="term-clear-btn" style="background:transparent; border:none; color:var(--text-muted); cursor:pointer;">[CLEAR]</button>
      </div>
    </div>
    <div class="terminal-body" id="term-body"></div>
    <div class="terminal-prompt-box">
      <span class="terminal-prompt">EOD-OSINT:~$</span>
      <input type="text" class="terminal-input" id="term-input" placeholder="Enter allowlisted command (e.g. 'help', 'status', 'sources')..." autocomplete="off" spellcheck="false" />
    </div>
  `;

  containerEl.appendChild(shell);

  const bodyEl = shell.querySelector('#term-body');
  const inputEl = shell.querySelector('#term-input');
  const clearBtn = shell.querySelector('#term-clear-btn');

  function renderLines() {
    if (!bodyEl) return;
    bodyEl.innerHTML = controller.lines
      .map(
        (line) =>
          `<div class="terminal-line ${line.type}">${escapeHtml(line.text)}</div>`
      )
      .join('');
    bodyEl.scrollTop = bodyEl.scrollHeight;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  controller.onOutput = () => {
    renderLines();
  };

  inputEl?.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
      const val = inputEl.value;
      inputEl.value = '';
      await controller.execute(val);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      inputEl.value = controller.history.navigateUp(inputEl.value);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      inputEl.value = controller.history.navigateDown();
    }
  });

  clearBtn?.addEventListener('click', () => {
    controller.lines = [];
    renderLines();
  });

  renderLines();
  return controller;
}
