/**
 * Vigil Background Service Worker
 * Manages extension badge, handles tab events, coordinates analysis.
 *
 * NOTE: The /analyze fetch lives HERE (not in content.js) because
 * Chrome blocks content-script → localhost requests via Private Network
 * Access rules. Service workers are exempt from that restriction.
 */

const BACKEND_URL = 'https://vigil-production-4c62.up.railway.app';

// Set default badge on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: '' });
  chrome.action.setBadgeBackgroundColor({ color: '#22C55E' });
  console.log('Vigil installed and active.');
});

// ── Main message handler ──────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── Analyze page (proxied fetch so localhost is reachable) ────────────────
  if (msg.type === 'ANALYZE_PAGE') {
    fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: msg.url, dom_data: msg.domData || {} }),
      signal: AbortSignal.timeout(5000),
    })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => sendResponse({ ok: true, data }))
      .catch(err => {
        console.warn('[Vigil] Backend fetch failed:', err.message);
        sendResponse({ ok: false, error: err.message });
      });

    return true; // keeps the message channel open for the async response
  }

  // ── Badge update ──────────────────────────────────────────────────────────
  if (msg.type === 'UPDATE_BADGE') {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    chrome.action.setBadgeText({ text: msg.text || '', tabId });
    chrome.action.setBadgeBackgroundColor({ color: msg.color || '#22C55E', tabId });
  }
});

// ── Clear badge + cached result on URL change ─────────────────────────────────
const tabUrls = {};

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    const prev = tabUrls[tabId];
    const curr = tab.url;

    if (prev !== curr) {
      tabUrls[tabId] = curr;
      chrome.action.setBadgeText({ text: '', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#64748B', tabId });

      chrome.storage.local.remove(['vigil_result', 'vigil_error']);
      chrome.storage.local.set({ vigil_url: curr, vigil_timestamp: 0 });
    }
  }
});

// Clean up on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabUrls[tabId];
});
