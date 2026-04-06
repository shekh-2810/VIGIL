/**
 * Vigil Extension — Popup Controller
 * ZeroDay Legends · VIT Bhopal · NextGen 2026
 *
 * Coding standards followed:
 *  - Strict CSP compliance (no innerHTML for user-supplied data)
 *  - const/let only (no var)
 *  - Named functions over anonymous where reuse is intended
 *  - Defensive null-checks on every DOM lookup
 *  - Settings persisted via chrome.storage.sync
 *  - Web Audio API for alert sound (no external assets needed)
 *  - All event listeners attached via addEventListener (no inline handlers)
 */

'use strict';

/* ── Constants ─────────────────────────────────────────────────────────────── */

const RISK_THRESHOLDS = Object.freeze({ SAFE: 30, SUSPICIOUS: 60 });

const SEVERITY_CLASSES = Object.freeze({
  high:   'sev-high',
  medium: 'sev-medium',
  low:    'sev-low',
});

const SVG = Object.freeze({
  ok: `<svg viewBox="0 0 24 24" fill="none" stroke="#22C55E" stroke-width="2.5" width="11" height="11" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>`,
  bad: `<svg viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.5" width="11" height="11" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  warn: `<svg viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2.5" width="11" height="11" aria-hidden="true"><path d="M12 2L2 20h20z"/><line x1="12" y1="9" x2="12" y2="14"/></svg>`,
});

/** In-memory scan history (session only; persisted scans would use storage). */
const scanHistory = [];

/* ── DOM helpers ────────────────────────────────────────────────────────────── */

/**
 * Safe getElementById wrapper — logs a warning if the element is missing.
 * @param {string} id
 * @returns {HTMLElement|null}
 */
function getEl(id) {
  const el = document.getElementById(id);
  if (!el) console.warn(`[Vigil] Element not found: #${id}`);
  return el;
}

/**
 * Set text content safely (never interprets as HTML).
 * @param {string} id
 * @param {string} text
 */
function setText(id, text) {
  const el = getEl(id);
  if (el) el.textContent = String(text);
}

/**
 * Toggle the .hidden utility class.
 * @param {string} id
 * @param {boolean} hide
 */
function setHidden(id, hide) {
  const el = getEl(id);
  if (el) el.classList.toggle('hidden', hide);
}

/* ── Risk classification ────────────────────────────────────────────────────── */

/**
 * @param {number} score 0-100
 * @returns {'safe'|'suspicious'|'dangerous'}
 */
function classifyRisk(score) {
  if (score < RISK_THRESHOLDS.SAFE) return 'safe';
  if (score < RISK_THRESHOLDS.SUSPICIOUS) return 'suspicious';
  return 'dangerous';
}

/**
 * @param {'safe'|'suspicious'|'dangerous'} level
 * @returns {string} CSS state class
 */
function stateClass(level) {
  const map = { safe: 'state-safe', suspicious: 'state-warn', dangerous: 'state-danger' };
  return map[level] || 'state-loading';
}

/**
 * @param {'safe'|'suspicious'|'dangerous'} level
 * @returns {string}
 */
function statusLabel(level) {
  const map = { safe: 'Site looks safe', suspicious: 'Suspicious site', dangerous: 'Phishing detected!' };
  return map[level] || 'Analyzing…';
}

/**
 * @param {number} score
 * @returns {string}
 */
function meterLabel(score) {
  if (score < 30) return 'Low';
  if (score < 60) return 'Moderate';
  if (score < 80) return 'High';
  return 'Critical';
}

/**
 * @param {number} score
 * @returns {string} hex colour
 */
function scoreColor(score) {
  if (score < 30) return '#22C55E';
  if (score < 60) return '#F59E0B';
  return '#EF4444';
}

/* ── Signal row updater ─────────────────────────────────────────────────────── */

/**
 * Update a signal row icon + value.
 * @param {string} baseId  e.g. 'sig-https'
 * @param {'ok'|'bad'|'warn'} type
 * @param {string} text
 */
function setSignal(baseId, type, text) {
  const icon = getEl(`${baseId}-icon`);
  const val  = getEl(baseId);
  if (!icon || !val) return;

  const iconClass = type === 'ok' ? 'icon-ok' : type === 'bad' ? 'icon-bad' : 'icon-warn';
  const valClass  = type === 'ok' ? 'val-ok'  : type === 'bad' ? 'val-bad'  : 'val-warn';

  icon.className = `signal-icon ${iconClass}`;
  icon.innerHTML = SVG[type] ?? SVG.warn;  // SVG is safe — it's our own constant

  val.textContent = text;
  val.className   = `signal-value ${valClass}`;
}

/* ── Alert sound (Web Audio API — no external files) ────────────────────────── */

/**
 * Plays a short tri-tone alert using the Web Audio API.
 * Called only when threat_score >= 60 AND the user has enabled alert sound.
 */
function playAlertSound() {
  try {
    const ctx        = new AudioContext();
    const gainNode   = ctx.createGain();
    gainNode.gain.setValueAtTime(0.18, ctx.currentTime);
    gainNode.connect(ctx.destination);

    /** @param {number} freq Hz @param {number} start seconds @param {number} dur seconds */
    const beep = (freq, start, dur) => {
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, ctx.currentTime + start);
      osc.connect(gainNode);
      osc.start(ctx.currentTime + start);
      osc.stop(ctx.currentTime + start + dur);
    };

    // Descending tri-tone — conveys "warning"
    beep(880, 0.00, 0.12);
    beep(660, 0.15, 0.12);
    beep(440, 0.30, 0.18);

    // Clean up context after sound finishes
    setTimeout(() => ctx.close(), 700);
  } catch (err) {
    console.warn('[Vigil] Audio playback failed:', err.message);
  }
}

/* ── Threat flags renderer ──────────────────────────────────────────────────── */

/**
 * Builds a single flag row element safely (no innerHTML with user data).
 * @param {{signal: string, description: string, severity: string}} flag
 * @returns {HTMLElement}
 */
function buildFlagRow(flag) {
  const row  = document.createElement('div');
  row.className = 'flag-row';

  const sev  = document.createElement('span');
  const sevClass = SEVERITY_CLASSES[flag.severity] || SEVERITY_CLASSES.low;
  sev.className = `flag-sev ${sevClass}`;
  sev.textContent = flag.severity;

  const body = document.createElement('div');
  body.className = 'flag-text';

  const name = document.createElement('div');
  name.className = 'flag-name';
  name.textContent = flag.signal;        // textContent — XSS safe

  const desc = document.createElement('div');
  desc.className = 'flag-desc';
  desc.textContent = flag.description;   // textContent — XSS safe

  body.appendChild(name);
  body.appendChild(desc);
  row.appendChild(sev);
  row.appendChild(body);
  return row;
}

/* ── History ────────────────────────────────────────────────────────────────── */

/**
 * Add a scan result to in-memory history and re-render.
 * @param {string} url
 * @param {number} score
 * @param {string} level
 */
function addToHistory(url, score, level) {
  let hostname = url;
  try { hostname = new URL(url).hostname; } catch (_) { /* keep raw url */ }

  scanHistory.unshift({ hostname, score, level, ts: Date.now() });
  if (scanHistory.length > 20) scanHistory.pop();
  renderHistory();
}

function renderHistory() {
  const container = getEl('history-list');
  if (!container) return;

  if (scanHistory.length === 0) return;

  const colorMap = { safe: '#22C55E', suspicious: '#F59E0B', dangerous: '#EF4444' };

  // Clear and rebuild safely
  container.textContent = '';

  scanHistory.forEach((entry) => {
    const item  = document.createElement('div');
    item.className = 'history-item';

    const dot   = document.createElement('div');
    dot.className = 'history-dot';
    dot.style.background = colorMap[entry.level] || '#64748B';

    const urlEl = document.createElement('span');
    urlEl.className = 'history-url';
    urlEl.textContent = entry.hostname;
    urlEl.title = entry.hostname;

    const scoreEl = document.createElement('span');
    scoreEl.className = 'history-score';
    scoreEl.textContent = `${entry.score}/100`;
    scoreEl.style.color = colorMap[entry.level] || '#64748B';

    item.appendChild(dot);
    item.appendChild(urlEl);
    item.appendChild(scoreEl);
    container.appendChild(item);
  });
}

/* ── Main render functions ──────────────────────────────────────────────────── */

/**
 * Render a successful analysis result into the popup UI.
 * @param {{threat_score:number, risk_level:string, flags:Array, analysis_ms:number}} result
 * @param {string} url
 */
function renderResult(result, url) {
  const score  = result.threat_score ?? 0;
  const level  = result.risk_level   ?? classifyRisk(score);
  const flags  = Array.isArray(result.flags) ? result.flags : [];
  const color  = scoreColor(score);

  // ── Status bar
  const statusBar = getEl('status-bar');
  if (statusBar) statusBar.className = `status-bar ${stateClass(level)}`;
  setText('status-label', statusLabel(level));
  setText('score-pill',   `Score: ${score}/100`);

  // ── URL display
  let displayHost = url;
  try { displayHost = new URL(url).hostname; } catch (_) { /* use raw */ }
  const urlEl = getEl('url-display');
  if (urlEl) { urlEl.textContent = displayHost; urlEl.title = url; }

  // ── SSL badge
  const sslBadge = getEl('ssl-badge');
  if (sslBadge) {
    const isHttps = url.startsWith('https');
    sslBadge.textContent = isHttps ? 'SSL valid' : 'No SSL';
    sslBadge.className   = `ssl-badge ${isHttps ? 'ssl-ok' : 'ssl-bad'}`;
  }

  // ── Threat meter
  const fill = getEl('meter-fill');
  if (fill) {
    fill.style.width      = `${score}%`;
    fill.style.background = color;
    const track = fill.closest('[role="progressbar"]');
    if (track) track.setAttribute('aria-valuenow', score);
  }
  const valEl = getEl('meter-val');
  if (valEl) { valEl.textContent = meterLabel(score); valEl.style.color = color; }

  // ── Signals
  setSignal('sig-https',
    url.startsWith('https') ? 'ok' : 'bad',
    url.startsWith('https') ? 'Secure' : 'Not encrypted');

  const homoglyphFlag = flags.find(
    (f) => /homoglyph|brand in sub/i.test(f.signal)
  );
  setSignal('sig-brand',
    homoglyphFlag ? 'bad' : 'ok',
    homoglyphFlag ? homoglyphFlag.signal : 'No mismatch');

  const formFlag = flags.find((f) => /form/i.test(f.signal));
  setSignal('sig-form',
    formFlag ? 'bad' : 'ok',
    formFlag ? 'Suspicious form' : 'Looks legitimate');

  const kwFlag = flags.find((f) => /keyword/i.test(f.signal));
  setSignal('sig-keywords',
    kwFlag ? (score > RISK_THRESHOLDS.SUSPICIOUS ? 'bad' : 'warn') : 'ok',
    kwFlag ? 'Suspicious terms found' : 'None detected');

  const tldFlag = flags.find((f) => /tld|domain/i.test(f.signal));
  setSignal('sig-tld',
    tldFlag ? 'warn' : 'ok',
    tldFlag ? tldFlag.signal : 'Normal');

  // ── Threat flags list
  const flagsSection = getEl('flags-section');
  const flagsList    = getEl('flags-list');

  if (flagsSection && flagsList) {
    if (flags.length > 0) {
      flagsList.textContent = '';          // Clear safely
      flags.forEach((f) => flagsList.appendChild(buildFlagRow(f)));
      flagsSection.classList.remove('hidden');
    } else {
      flagsSection.classList.add('hidden');
    }
  }

  // ── Action button
  const btnMain = getEl('btn-main');
  if (btnMain) {
    btnMain.classList.remove('hidden');
    if (level === 'safe') {
      btnMain.textContent = '✓ Site looks safe';
      btnMain.className   = 'btn btn-primary';
      btnMain.onclick     = null;
    } else {
      btnMain.textContent = '← Go back to safety';
      btnMain.className   = 'btn btn-danger';
      btnMain.onclick     = handleGoBack;
    }
  }

  // ── Footer
  const footerMap = { safe: 'No threats detected', suspicious: 'Caution advised', dangerous: 'Threat blocked' };
  setText('footer-status', footerMap[level] || '');
  setText('footer-ms', result.analysis_ms ? `${result.analysis_ms}ms` : '');

  // ── Alert sound (if enabled and risky)
  chrome.storage.sync.get({ alertSound: false }, (prefs) => {
    if (prefs.alertSound && score >= RISK_THRESHOLDS.SUSPICIOUS) {
      playAlertSound();
    }
  });

  // ── History
  addToHistory(url, score, level);
}

/**
 * Render an error / offline state.
 * @param {string|null} url
 */
function renderError(url) {
  const statusBar = getEl('status-bar');
  if (statusBar) statusBar.className = 'status-bar state-loading';
  setText('status-label', 'Backend offline');
  setText('score-pill',   '—');

  let display = '—';
  if (url) {
    try { display = new URL(url).hostname; } catch (_) { display = url.slice(0, 40); }
  }
  setText('url-display', display);
  setText('footer-status', 'Run: uvicorn app:app --port 8000');
  setText('footer-ms', '');

  const liveDot = getEl('live-dot');
  if (liveDot) liveDot.classList.add('offline');
}

/**
 * Render the transient loading / scanning state.
 */
function renderLoading() {
  const statusBar = getEl('status-bar');
  if (statusBar) statusBar.className = 'status-bar state-loading';
  setText('status-label', 'Analyzing…');
  setText('score-pill',   '—');
  setText('footer-status', 'Scanning page…');
  setText('footer-ms', '');
}

/* ── Navigation ─────────────────────────────────────────────────────────────── */

function handleGoBack() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) chrome.tabs.goBack(tabs[0].id);
  });
}

/* ── Tab switching ──────────────────────────────────────────────────────────── */

function initTabs() {
  const tabs  = document.querySelectorAll('.tab');
  const views = document.querySelectorAll('.view');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      if (!target) return;

      tabs.forEach((t)  => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      views.forEach((v) => v.classList.remove('active'));

      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');

      const view = document.getElementById(`view-${target}`);
      if (view) view.classList.add('active');
    });
  });
}

/* ── Settings ───────────────────────────────────────────────────────────────── */

const SENS_LABELS = ['Relaxed', 'Balanced', 'Strict'];

function initSettings() {
  // Load saved preferences from chrome.storage.sync
  const toggleIds = ['tog-protection', 'tog-intercept', 'tog-dom', 'tog-sound', 'tog-reports'];
  const defaults  = {
    protection: true,
    intercept:  true,
    dom:        true,
    alertSound: false,
    reports:    true,
    sensitivity: 2,
  };

  chrome.storage.sync.get(defaults, (prefs) => {
    toggleIds.forEach((id) => {
      const el = getEl(id);
      if (!el) return;
      const key = id.replace('tog-', '');
      const prefKey = key === 'sound' ? 'alertSound' : key;
      el.checked = !!prefs[prefKey];
    });

    const slider = getEl('sens-slider');
    if (slider) slider.value = prefs.sensitivity;
    setText('sens-label', SENS_LABELS[prefs.sensitivity - 1] || 'Balanced');
  });

  // Save on change
  toggleIds.forEach((id) => {
    const el = getEl(id);
    if (!el) return;
    el.addEventListener('change', () => {
      const key = id.replace('tog-', '');
      const prefKey = key === 'sound' ? 'alertSound' : key;
      chrome.storage.sync.set({ [prefKey]: el.checked });
    });
  });

  const sensSlider = getEl('sens-slider');
  if (sensSlider) {
    sensSlider.addEventListener('input', () => {
      const val = Number(sensSlider.value);
      setText('sens-label', SENS_LABELS[val - 1] || 'Balanced');
      chrome.storage.sync.set({ sensitivity: val });
    });
  }
}

/* ── Rescan ─────────────────────────────────────────────────────────────────── */

function initRescan() {
  const btn = getEl('btn-rescan');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    renderLoading();
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs[0]) return;
      const tab = tabs[0];

      // Reset timestamp so waitForResult knows to wait for a genuinely new result
      await chrome.storage.local.set({ vigil_timestamp: 0, vigil_result: null });

      // Trigger content script to re-analyze
      chrome.tabs.sendMessage(tab.id, { type: 'REANALYZE' }, () => {
        // Ignore response — we'll poll storage instead, which is the source of truth
        if (chrome.runtime.lastError) {
          renderError(tab.url);
        }
      });

      // Poll for fresh result
      const result = await waitForResult(tab.url, 6000);
      if (result) renderResult(result, tab.url);
      else renderError(tab.url);
    });
  });
}

/* ── Init ───────────────────────────────────────────────────────────────────── */

/**
 * Poll chrome.storage.local for a fresh analysis result.
 * The content script fires ~800ms after page load, so we wait up to 5s.
 * @param {string} expectedUrl - URL we're waiting for
 * @param {number} [maxWaitMs=5000]
 * @returns {Promise<object|null>} Resolves with result or null on timeout
 */
function waitForResult(expectedUrl, maxWaitMs = 5000) {
  return new Promise((resolve) => {
    const interval = 300;
    let elapsed = 0;

    const poll = () => {
      chrome.storage.local.get(['vigil_result', 'vigil_url', 'vigil_error', 'vigil_timestamp'], (data) => {
        const fresh = data.vigil_result &&
                      data.vigil_url === expectedUrl &&
                      data.vigil_timestamp > 0;

        if (fresh) {
          resolve(data.vigil_result);
          return;
        }

        if (data.vigil_error && data.vigil_url === expectedUrl) {
          resolve(null);  // backend is offline
          return;
        }

        elapsed += interval;
        if (elapsed >= maxWaitMs) {
          resolve(null);  // timed out
          return;
        }

        setTimeout(poll, interval);
      });
    };

    poll();
  });
}

/**
 * Entry point — called once DOM is ready (script tag is at end of body).
 */
function init() {
  initTabs();
  initSettings();
  initRescan();

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) { renderLoading(); return; }
    const tab = tabs[0];
    const tabUrl = tab.url || '';

    // Show the URL immediately — never leave it blank
    let displayHost = tabUrl;
    try { displayHost = new URL(tabUrl).hostname; } catch (_) { /* use raw */ }
    const urlEl = getEl('url-display');
    if (urlEl) { urlEl.textContent = displayHost; urlEl.title = tabUrl; }

    // First try cache
    chrome.storage.local.get(['vigil_result', 'vigil_url', 'vigil_error', 'vigil_timestamp'], async (data) => {
      if (chrome.runtime.lastError) { renderLoading(); return; }

      const age     = Date.now() - (data.vigil_timestamp || 0);
      const sameUrl = data.vigil_url === tabUrl;
      const fresh   = sameUrl && age < 30_000 && age > 0;

      if (data.vigil_result && fresh) {
        // Cache hit — render immediately
        renderResult(data.vigil_result, tabUrl);
        return;
      }

      // Cache miss — show scanning state and wait for content script to finish
      renderLoading();

      const result = await waitForResult(tabUrl, 5000);

      if (result) {
        renderResult(result, tabUrl);
      } else {
        // Content script timed out or backend offline — show error
        renderError(tabUrl);
      }
    });
  });
}

// DOM is guaranteed ready since this script is at the end of <body>
init();
