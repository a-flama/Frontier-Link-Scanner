/* Phase 2+ content script:
   - Heuristic scoring (OK/WARN/DANGER)
   - Risky-click interceptor
   - "Show full URL" button calls background resolve()
   - Optional: VT check using user-supplied key (background vtCheck)
   - Hallucinated link signal via DoH domain existence (background doh)
*/
console.log("[AI Link Guard] content script loaded");

// ---------- Badge UI ----------
function upsertBadge(anchor, verdict) {
  // verdict = { level: "ok"|"warn"|"danger"|"hall", label: "OK"|"WARN"|"DANGER"|"HALL", reasons: [], source?: string }
  if (anchor._aiBadgeEl) {
    anchor._aiBadgeEl.remove();
    delete anchor._aiBadgeEl;
  }

  const tag = document.createElement("span");
  const glyph =
    verdict.label === "OK"   ? "✅" :
    verdict.label === "WARN" ? "⚠️" :
    verdict.label === "HALL" ? "❔" : "❌";
  tag.textContent = glyph;
  const reasonText = verdict.reasons?.length ? verdict.reasons.join(" • ") : verdict.label;
  tag.title = `${verdict.source || "heuristic"} • ${reasonText}`;

  const bg = verdict.level === "danger" ? "#ffe3e3"
           : verdict.level === "warn"   ? "#fff6d6"
           : verdict.level === "hall"   ? "#e6f0ff"
           : "#e7f9e7";
  const bd = verdict.level === "danger" ? "#e66"
           : verdict.level === "warn"   ? "#e6c200"
           : verdict.level === "hall"   ? "#6aa0ff"
           : "#6c6";

  tag.style.cssText = `
    display:inline-block;margin-left:6px;padding:0 6px;border-radius:10px;
    font: 12px/18px system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background:${bg}; border:1px solid ${bd}; color:#222; user-select:none;
  `;
  anchor.insertAdjacentElement("afterend", tag);
  anchor._aiBadgeEl = tag;

  // Risky-click confirmation
  if (!anchor.dataset.aiClickGuarded) {
    anchor.dataset.aiClickGuarded = "1";
    anchor.addEventListener("click", (e) => {
      const s = scoreUrlHeuristics(anchor.href, pageIsHttps());
      if (s.score >= 30) {
        e.preventDefault();
        const head = s.score >= 60 ? "⚠️ This link looks dangerous.\n" : "⚠️ This link may be risky.\n";
        const reasons = s.reasons.length ? `Reasons: ${s.reasons.join(", ")}\n` : "";
        const proceed = confirm(head + reasons + "Open anyway?");
        if (proceed) window.open(anchor.href, "_blank", "noopener");
      }
    }, { capture: true });
  }

  // Ensure button wrap exists
  if (!anchor._aiButtonsEl) {
    const wrap = document.createElement("span");
    wrap.style.marginLeft = "6px";
    anchor.insertAdjacentElement("afterend", wrap);
    anchor._aiButtonsEl = wrap;
  }
}

// ---------- "Show full URL" button ----------
function ensureShowFullUrlButton(anchor) {
  if (!anchor._aiButtonsEl) {
    const wrap = document.createElement("span");
    wrap.style.marginLeft = "6px";
    anchor.insertAdjacentElement("afterend", wrap);
    anchor._aiButtonsEl = wrap;
  }

  if (!anchor._aiShowBtn) {
    const btn = document.createElement("button");
    btn.textContent = "Show full URL";
    btn.style.cssText = [
      "margin-left:4px",
      "padding:0 6px",
      "font-size:11px",
      "border:1px solid #aaa",
      "border-radius:6px",
      "background:#fff",
      "color:#111",
      "cursor:pointer"
    ].join(";") + ";";
    btn.addEventListener("click", async (e) => {
      e.preventDefault(); e.stopPropagation();
      try {
        const resp = await chrome.runtime.sendMessage({ type: "resolve", url: anchor.href });
        if (resp && resp.finalUrl) {
          const chain = (resp.redirects || []).concat([resp.finalUrl]);
          alert("Redirect chain:\n" + chain.join("\n→ "));
        } else if (resp && resp.error) {
          alert("Unable to resolve redirects.\nError: " + resp.error);
        } else {
          alert("Unable to resolve redirects.");
        }
      } catch (err) {
        alert("Error resolving URL: " + String(err));
      }
    }, { capture: true });
    anchor._aiButtonsEl.appendChild(btn);
    anchor._aiShowBtn = btn;
  }
}

// ---------- Heuristics ----------
const IDN_REGEX = /xn--/i;
const DANGEROUS_EXT = /\.(exe|msi|scr|js|vbs|apk|pkg|iso)(\?|#|$)/i;
const ARCHIVE_EXT = /\.(zip|rar|7z)(\?|#|$)/i;
const SHORTENERS = new Set(["bit.ly","t.co","goo.gl","tinyurl.com","ow.ly","is.gd","rebrand.ly","cutt.ly","rb.gy","s.id","lnkd.in"]);
const SUSPICIOUS_WORDS = [/login/i, /verify/i, /reset/i, /invoice/i, /gift/i, /download/i, /wallet/i, /seed/i];
const RISKY_TLDS = new Set(["top","xyz","click","cam","monster","gq","cf","tk","ml"]);
function pageIsHttps() { return location.protocol === "https:"; }

function scoreUrlHeuristics(raw, isPageHttps) {
  let s = 0, reasons = [];
  let url;
  try { url = new URL(raw); } catch { return { score: 70, reasons: ["Malformed URL"] }; }

  if (url.protocol !== "https:") { s += 30; reasons.push("Non-HTTPS"); }
  const host = url.hostname.toLowerCase();
  if (IDN_REGEX.test(host)) { s += 30; reasons.push("IDN/punycode"); }
  if ([...host].some(ch => ch.charCodeAt(0) > 127)) { s += 15; reasons.push("Unicode hostname"); }
  if (SHORTENERS.has(host)) { s += 15; reasons.push("Shortener/redirector"); }
  const tld = host.split(".").pop();
  if (RISKY_TLDS.has(tld)) { s += 10; reasons.push(`Risky TLD .${tld}`); }

  const pathq = (url.pathname || "") + (url.search || "");
  if (DANGEROUS_EXT.test(url.pathname)) { s += 60; reasons.push("Executable download"); }
  if (ARCHIVE_EXT.test(url.pathname)) { s += 30; reasons.push("Archive download"); }
  if (pathq.length > 200) { s += 10; reasons.push("Very long query/path"); }
  if ((raw.match(/@/g) || []).length > 1) { s += 10; reasons.push("Multiple @"); }
  if (/%00|%2f/i.test(raw)) { s += 10; reasons.push("Encoded null/slash"); }
  if (SUSPICIOUS_WORDS.some(rx => rx.test(pathq))) { s += 10; reasons.push("Suspicious keywords"); }

  if (url.port && !["","80","443"].includes(url.port)) { s += 10; reasons.push(`Uncommon port :${url.port}`); }
  if (isPageHttps && url.protocol === "http:") { s += 15; reasons.push("Mixed content (HTTP link from HTTPS page)"); }

  return { score: s, reasons };
}
function verdictFromScore(score, reasons) {
  if (score >= 60) return { level: "danger", label: "DANGER", reasons };
  if (score >= 30) return { level: "warn", label: "WARN", reasons };
  return { level: "ok", label: "OK", reasons };
}

// ---------- Scope (avoid sidebar) ----------
const ALLOW_CONTAINERS = [
  'main [data-testid="conversation-turn"]',
  'main .markdown',
  'main .prose',
  'main .overflow-y-auto'
];
const DENY_CONTAINERS = ['nav','aside','header','footer','[role="navigation"]','[aria-label="Sidebar"]','[data-testid="left-nav"]'];

function findAnchors(root = document) {
  const baseRoots = ALLOW_CONTAINERS.map(sel => Array.from(root.querySelectorAll(`${sel} a[href]`))).flat();
  const anchors = baseRoots.length ? baseRoots : Array.from(root.querySelectorAll('a[href]'));
  return anchors.filter(a => !a.closest(DENY_CONTAINERS.join(',')));
}

// ---------- Main pipeline ----------
async function annotate(anchor) {
  if (anchor.dataset.aiBootstrapChecked) return;
  anchor.dataset.aiBootstrapChecked = "1";

  // 1) Heuristics
  const h = scoreUrlHeuristics(anchor.href, pageIsHttps());
  const hVerdict = { ...verdictFromScore(h.score, h.reasons), source: "heuristic" };
  upsertBadge(anchor, hVerdict);

  // 2) "Show full URL"
  ensureShowFullUrlButton(anchor);

  // 3) Hallucination check (DNS)
  try {
    const host = new URL(anchor.href).hostname;
    chrome.runtime.sendMessage({ type: "doh", domain: host }, (resp) => {
      if (resp && resp.exists === false) {
        upsertBadge(anchor, { level: "hall", label: "HALL", reasons: ["Domain does not resolve — possible hallucinated link"], source: "doh" });
      }
    });
  } catch {}

  // 4) VirusTotal check (if user set a key)
  chrome.runtime.sendMessage({ type: "vtCheck", url: anchor.href }, (vt) => {
    if (!vt) return;
    if (vt.error === "no_key") {
      anchor._aiBadgeEl && (anchor._aiBadgeEl.title += " • VT:not configured");
      return;
    }
    if (vt.error) {
      anchor._aiBadgeEl && (anchor._aiBadgeEl.title += ` • VT:${vt.error}`);
      return;
    }
    if (vt.malicious) {
      upsertBadge(anchor, { level: "danger", label: "DANGER", reasons: ["VirusTotal flagged"], source: "virustotal" });
    } else if (vt.clean) {
      upsertBadge(anchor, { level: "ok", label: "OK", reasons: ["No VT engines detected"], source: "virustotal" });
    } else {
      anchor._aiBadgeEl && (anchor._aiBadgeEl.title += " • VT:unknown");
    }
  });
}

function scanExisting(root = document) { findAnchors(root).forEach(annotate); }

const observeRoot = document.querySelector('main') || document.body;
const observer = new MutationObserver(muts => {
  for (const m of muts) {
    m.addedNodes.forEach(n => { if (n.nodeType === 1) findAnchors(n).forEach(annotate); });
  }
});
observer.observe(observeRoot, { childList: true, subtree: true });

// Initial scans (both to be safe)
scanExisting(observeRoot);
scanExisting(document);

// Manual rescan
window.__aiLinkGuardRescan = () => { scanExisting(observeRoot); scanExisting(document); };
