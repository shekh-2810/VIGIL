/**
 * Vigil Content Script
 * Runs on every page. Does three things:
 *   1. Extracts DOM signals (login forms, hidden fields, obfuscated JS, etc.)
 *   2. Sends URL + DOM data to background.js which proxies to the ML backend
 *   3. Intercepts form submissions on high-risk pages and shows threat modal
 *
 * NOTE: fetch() to localhost is NOT done here — Chrome's Private Network
 * Access policy blocks content-script → 127.0.0.1 requests. The background
 * service worker (background.js) handles the actual HTTP call instead.
 */

const INTERCEPT_THRESHOLD = 60; // threat_score above this = block form submission

let analysisResult = null;
let interceptActive = false;

// ── DOM Signal Extraction ─────────────────────────────────────────────────────
function extractDomData() {
  const forms = document.querySelectorAll('form');
  const inputs = document.querySelectorAll('input');
  const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
  const passwordFields = document.querySelectorAll('input[type="password"]');
  const iframes = document.querySelectorAll('iframe');
  const links = document.querySelectorAll('a');
  const scripts = document.querySelectorAll('script');

  const currentHost = window.location.hostname;

  // Check if any form submits to a different domain
  let formActionMismatch = false;
  let hasExternalFormAction = false;
  forms.forEach(form => {
    const action = form.action || '';
    if (action && !action.startsWith(window.location.origin)) {
      hasExternalFormAction = true;
      try {
        const actionHost = new URL(action).hostname;
        if (actionHost && actionHost !== currentHost) {
          formActionMismatch = true;
        }
      } catch (e) {}
    }
  });

  // Favicon domain check
  let faviconMismatch = false;
  const faviconEl = document.querySelector('link[rel*="icon"]');
  if (faviconEl && faviconEl.href) {
    try {
      const favHost = new URL(faviconEl.href).hostname;
      if (favHost && favHost !== currentHost && !favHost.endsWith('.' + currentHost)) {
        faviconMismatch = true;
      }
    } catch (e) {}
  }

  // Copyright text detection
  const bodyText = document.body ? document.body.innerText || '' : '';
  const hasCopyright = /©|copyright|\(c\)/i.test(bodyText);

  // JS obfuscation detection
  let hasObfuscatedJs = false;
  scripts.forEach(s => {
    const content = s.textContent || '';
    if (
      /eval\s*\(/.test(content) ||
      /unescape\s*\(/.test(content) ||
      /String\.fromCharCode/.test(content) ||
      /\\x[0-9a-fA-F]{2}/.test(content) ||
      content.length > 5000 && /[A-Za-z0-9+/]{200,}={0,2}/.test(content)
    ) {
      hasObfuscatedJs = true;
    }
  });

  // External links ratio
  let externalLinks = 0;
  links.forEach(a => {
    try {
      if (a.href && new URL(a.href).hostname !== currentHost) externalLinks++;
    } catch (e) {}
  });
  const linkRatio = links.length > 0 ? externalLinks / links.length : 0;

  // Right-click disabled
  const hasRightClickDisabled = document.body ?
    (document.body.oncontextmenu !== null ||
     document.documentElement.getAttribute('oncontextmenu') !== null) : false;

  const hasPopup = typeof window.onbeforeunload === 'function';

  return {
    has_password_field: passwordFields.length > 0,
    has_login_form: passwordFields.length > 0 && forms.length > 0,
    num_inputs: inputs.length,
    num_hidden_inputs: hiddenInputs.length,
    form_action_domain_mismatch: formActionMismatch,
    has_external_form_action: hasExternalFormAction,
    favicon_domain_mismatch: faviconMismatch,
    has_copyright_text: hasCopyright,
    num_iframes: iframes.length,
    has_obfuscated_js: hasObfuscatedJs,
    num_external_links: externalLinks,
    link_to_text_ratio: Math.round(linkRatio * 100) / 100,
    has_right_click_disabled: hasRightClickDisabled,
    has_popup: hasPopup,
    page_title: document.title || '',
  };
}

// ── Backend call via background service worker ────────────────────────────────
async function analyzeCurrentPage() {
  const url = window.location.href;
  const domData = extractDomData();

  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { type: 'ANALYZE_PAGE', url, domData },
      (response) => {
        // Handle extension context errors gracefully
        if (chrome.runtime.lastError) {
          console.warn('[Vigil] Message error:', chrome.runtime.lastError.message);
          chrome.storage.local.set({
            vigil_result: null,
            vigil_url: url,
            vigil_error: 'Extension error',
            vigil_timestamp: Date.now(),
          });
          resolve(null);
          return;
        }

        if (!response || !response.ok) {
          // Backend is offline or returned an error
          chrome.storage.local.set({
            vigil_result: null,
            vigil_url: url,
            vigil_error: 'Backend offline',
            vigil_timestamp: Date.now(),
          });
          resolve(null);
          return;
        }

        const result = response.data;
        analysisResult = result;

        chrome.storage.local.set({
          vigil_result: result,
          vigil_url: url,
          vigil_timestamp: Date.now(),
        });

        updateBadge(result.threat_score, result.risk_level);

        if (result.threat_score >= INTERCEPT_THRESHOLD) {
          setupFormIntercept(result);
        }

        resolve(result);
      }
    );
  });
}

// ── Badge update ──────────────────────────────────────────────────────────────
function updateBadge(score, riskLevel) {
  const color = riskLevel === 'safe' ? '#22C55E' :
                riskLevel === 'suspicious' ? '#F59E0B' : '#EF4444';
  const text = score >= 60 ? score.toString() : '';

  chrome.runtime.sendMessage({
    type: 'UPDATE_BADGE',
    score,
    riskLevel,
    color,
    text,
  }).catch(() => {});
}

// ── Threat Modal (pre-submit intercept) ───────────────────────────────────────
function createThreatModal(result) {
  const existing = document.getElementById('vigil-threat-modal');
  if (existing) existing.remove();

  const flags = result.flags || [];
  const flagsHtml = flags.slice(0, 5).map(f => `
    <div class="vigil-flag">
      <div class="vigil-flag-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.5" width="11" height="11">
          <path d="M12 2L3 7v6c0 5 4 9.3 9 10.5C17 22.3 21 18 21 13V7z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r="0.5" fill="#EF4444"/>
        </svg>
      </div>
      <div class="vigil-flag-body">
        <div class="vigil-flag-title">${escapeHtml(f.signal)}</div>
        <div class="vigil-flag-desc">${escapeHtml(f.description)}</div>
      </div>
    </div>
  `).join('');

  const modal = document.createElement('div');
  modal.id = 'vigil-threat-modal';
  modal.innerHTML = `
    <style>
      #vigil-threat-modal {
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(0,0,0,0.85);
        display: flex; align-items: center; justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      #vigil-modal-box {
        background: #0F172A; border-radius: 14px;
        border: 2px solid #EF4444; width: 92%; max-width: 440px;
        overflow: hidden; box-shadow: 0 25px 60px rgba(0,0,0,0.6);
        animation: vigil-in 0.25s ease;
      }
      @keyframes vigil-in {
        from { transform: scale(0.92) translateY(10px); opacity: 0; }
        to   { transform: scale(1) translateY(0); opacity: 1; }
      }
      .vigil-modal-top {
        background: #1C0A0A; padding: 24px 20px 20px;
        text-align: center; border-bottom: 1px solid rgba(239,68,68,0.2);
      }
      .vigil-shield-icon {
        width: 56px; height: 56px; border-radius: 50%;
        background: #450A0A; border: 2px solid #EF4444;
        display: flex; align-items: center; justify-content: center;
        margin: 0 auto 14px;
      }
      .vigil-modal-title { font-size: 18px; font-weight: 600; color: #EF4444; margin-bottom: 5px; }
      .vigil-modal-url {
        font-size: 12px; color: #FCA5A5;
        font-family: 'Courier New', monospace;
        word-break: break-all; margin-bottom: 10px;
      }
      .vigil-score-pill {
        display: inline-block; background: #450A0A; color: #FCA5A5;
        font-size: 12px; font-weight: 600; padding: 3px 14px;
        border-radius: 20px; border: 1px solid rgba(239,68,68,0.3);
      }
      .vigil-modal-body { padding: 16px 20px; }
      .vigil-flags-label {
        font-size: 10px; color: #475569;
        text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 12px;
      }
      .vigil-flag {
        display: flex; align-items: flex-start; gap: 10px;
        padding: 8px 0; border-bottom: 1px solid #1E293B;
      }
      .vigil-flag:last-child { border-bottom: none; }
      .vigil-flag-icon {
        width: 22px; height: 22px; border-radius: 5px;
        background: #450A0A; display: flex; align-items: center;
        justify-content: center; flex-shrink: 0; margin-top: 1px;
      }
      .vigil-flag-body { flex: 1; }
      .vigil-flag-title { font-size: 13px; color: #F8FAFC; font-weight: 500; }
      .vigil-flag-desc { font-size: 11px; color: #64748B; margin-top: 2px; line-height: 1.4; }
      .vigil-modal-actions {
        padding: 14px 20px; display: flex; gap: 10px;
        border-top: 1px solid #1E293B;
      }
      .vigil-btn-safe {
        flex: 2; padding: 11px; border-radius: 8px;
        background: #22C55E; color: #052E16;
        font-size: 13px; font-weight: 600; border: none; cursor: pointer;
      }
      .vigil-btn-safe:hover { background: #16A34A; }
      .vigil-btn-risk {
        flex: 1; padding: 11px; border-radius: 8px;
        background: #1E293B; color: #64748B;
        font-size: 13px; border: 1px solid #334155; cursor: pointer;
      }
      .vigil-btn-risk:hover { color: #94A3B8; }
      .vigil-footnote {
        padding: 0 20px 14px;
        font-size: 10px; color: #334155; text-align: center;
      }
    </style>

    <div id="vigil-modal-box">
      <div class="vigil-modal-top">
        <div class="vigil-shield-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2" width="26" height="26">
            <path d="M12 2L3 7v6c0 5 4 9.3 9 10.5C17 22.3 21 18 21 13V7z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <circle cx="12" cy="17" r="0.8" fill="#EF4444"/>
          </svg>
        </div>
        <div class="vigil-modal-title">⚠ Phishing Detected</div>
        <div class="vigil-modal-url">${escapeHtml(window.location.hostname)}</div>
        <div class="vigil-score-pill">Threat Score: ${result.threat_score}/100</div>
      </div>

      <div class="vigil-modal-body">
        <div class="vigil-flags-label">Why Vigil flagged this page</div>
        ${flagsHtml || '<div style="font-size:12px;color:#64748B;">ML model detected unusual URL patterns.</div>'}
      </div>

      <div class="vigil-modal-actions">
        <button class="vigil-btn-safe" id="vigil-btn-safe">← Go back to safety</button>
        <button class="vigil-btn-risk" id="vigil-btn-risk">Ignore risk</button>
      </div>
      <div class="vigil-footnote">
        Vigil blocked form submission · Your credentials were not sent
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  document.getElementById('vigil-btn-safe').addEventListener('click', () => {
    window.history.back();
    modal.remove();
  });

  document.getElementById('vigil-btn-risk').addEventListener('click', () => {
    modal.remove();
    interceptActive = false;
  });
}

// ── Form interception ─────────────────────────────────────────────────────────
function setupFormIntercept(result) {
  if (interceptActive) return;
  interceptActive = true;

  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', (e) => {
      if (interceptActive) {
        e.preventDefault();
        e.stopImmediatePropagation();
        createThreatModal(result);
      }
    }, true);
  });

  const observer = new MutationObserver(() => {
    document.querySelectorAll('form:not([data-vigil])').forEach(form => {
      form.setAttribute('data-vigil', '1');
      form.addEventListener('submit', (e) => {
        if (interceptActive) {
          e.preventDefault();
          e.stopImmediatePropagation();
          createThreatModal(result);
        }
      }, true);
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

// ── Utility ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Listen for messages from popup ───────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'GET_DOM_DATA') {
    sendResponse(extractDomData());
  }
  if (msg.type === 'GET_ANALYSIS') {
    sendResponse(analysisResult);
  }
  if (msg.type === 'REANALYZE') {
    analyzeCurrentPage().then(r => sendResponse(r));
    return true; // async
  }
});

// ── Run analysis on page load ─────────────────────────────────────────────────
setTimeout(() => {
  analyzeCurrentPage();
}, 800);
