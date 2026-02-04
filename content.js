// Broadened selectors to capture the dynamic message pane in Outlook and Gmail
const EMAIL_BODY_SELECTORS = [
  '.adn.ads',                   // Gmail
  '[role="main"]',              // Outlook Main Pane
  '[aria-label="Message body"]', // Outlook Message Body
  '.wide-content-host',         // Modern Outlook/Hotmail specific
  '#Item.MessagePartBody'       // Outlook Legacy/Embedded
];

function annotate(anchor) {
  // Filter out non-links and already scanned ones
  if (anchor.dataset.scanned || !anchor.href.startsWith('http')) return;
  anchor.dataset.scanned = "1";

  chrome.runtime.sendMessage({ type: "vtCheck", url: anchor.href }, (res) => {
    if (!res || res.error) return;
    
    const badge = document.createElement("span");
    const isMalicious = res.malicious;
    
    badge.textContent = isMalicious ? "⚠️ DANGER" : "✅ OK";
    
    // Styling the badge to look clean in dark mode (as seen in your screenshot)
    badge.style.cssText = `
      margin-left: 10px;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-family: sans-serif;
      font-weight: bold;
      color: white;
      display: inline-block;
      vertical-align: middle;
      background: ${isMalicious ? '#ff4d4d' : '#28a745'};
      border: 1px solid ${isMalicious ? '#b30000' : '#1e7e34'};
    `;
    
    anchor.after(badge);
  });
}

// Outlook swaps content within the same container; we observe everything to be safe
const observer = new MutationObserver(() => {
  EMAIL_BODY_SELECTORS.forEach(selector => {
    const containers = document.querySelectorAll(selector);
    containers.forEach(container => {
      // Find all links that haven't been tagged yet
      const links = container.querySelectorAll('a[href]:not([data-scanned])');
      links.forEach(annotate);
    });
  });
});

// Observe the entire document to catch the message as it renders
observer.observe(document.body, { 
  childList: true, 
  subtree: true 
});

// Run a check immediately in case the email is already open
EMAIL_BODY_SELECTORS.forEach(selector => {
  document.querySelectorAll(`${selector} a[href]`).forEach(annotate);
});