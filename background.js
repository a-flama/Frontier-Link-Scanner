// Background service worker: optional VirusTotal via user key, DNS-over-HTTPS domain checks, redirect resolution.

const CACHE_TTL = 24 * 60 * 60 * 1000; // 24h
const cache = new Map(); // key -> { ts, data }
const DOH_GOOGLE = "https://dns.google/resolve?name=";
// const DOH_CF = "https://cloudflare-dns.com/dns-query?name="; // alt if you want

function cacheGet(key) {
  const v = cache.get(key);
  if (!v) return null;
  if (Date.now() - v.ts > CACHE_TTL) { cache.delete(key); return null; }
  return v.data;
}
function cacheSet(key, data) { cache.set(key, { ts: Date.now(), data }); }

chrome.runtime.onInstalled.addListener(() => {
  console.log("[AI Link Guard] background installed");
});

// ---------- VirusTotal (user-supplied key) ----------
function base64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function vtUrlCheckWithUserKey(url) {
  const { vt_api_key } = await chrome.storage.local.get(["vt_api_key"]);
  if (!vt_api_key) return { error: "no_key" };

  const ck = `vt:${url}`;
  const cached = cacheGet(ck);
  if (cached !== null) return cached;

  try {
    const id = base64url(url);
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": vt_api_key }
    });

    if (r.status === 404) {
      // Not known to VT (we won't submit automatically to avoid quota burn)
      const out = { unknown: true };
      cacheSet(ck, out);
      return out;
    }

    if (!r.ok) {
      const out = { error: `vt_http_${r.status}` };
      cacheSet(ck, out);
      return out;
    }

    const j = await r.json();
    const stats = j?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0) > 0;
    const suspicious = Number(stats.suspicious || 0) > 0;
    const out = {
      clean: !malicious && !suspicious,
      malicious: malicious || suspicious,
      stats,
      permalink: j?.data?.links?.self || null
    };
    cacheSet(ck, out);
    return out;
  } catch (e) {
    const out = { error: String(e) };
    cacheSet(ck, out);
    return out;
  }
}

// ---------- DNS over HTTPS: does domain resolve? (hallucinated link signal) ----------
async function domainExists(domain) {
  const ck = `doh:${domain}`;
  const cached = cacheGet(ck);
  if (cached !== null) return cached;

  try {
    const r = await fetch(`${DOH_GOOGLE}${encodeURIComponent(domain)}&type=A`, { method: "GET" });
    if (!r.ok) { cacheSet(ck, false); return false; }
    const j = await r.json();
    const exists = Array.isArray(j.Answer) && j.Answer.length > 0;
    cacheSet(ck, exists);
    return exists;
  } catch {
    cacheSet(ck, false);
    return false;
  }
}

// ---------- Redirect resolution (background fetch) ----------
async function resolveRedirects(rawUrl, timeoutMs = 10000) {
  const ck = `resolve:${rawUrl}`;
  const cached = cacheGet(ck);
  if (cached !== null) return cached;

  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(rawUrl, { method: "GET", redirect: "follow", signal: controller.signal });
    clearTimeout(id);
    const finalUrl = resp.url || rawUrl;
    const data = { finalUrl, redirects: finalUrl === rawUrl ? [] : [rawUrl] };
    cacheSet(ck, data);
    return data;
  } catch (e) {
    const out = { error: String(e) };
    cacheSet(ck, out);
    return out;
  }
}

// ---------- Message handlers ----------
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "vtCheck" && msg.url) {
    (async () => {
      const res = await vtUrlCheckWithUserKey(msg.url);
      sendResponse(res);
    })();
    return true;
  }

  if (msg.type === "resolve" && msg.url) {
    (async () => {
      const res = await resolveRedirects(msg.url);
      sendResponse(res);
    })();
    return true;
  }

  if (msg.type === "doh" && msg.domain) {
    (async () => {
      const exists = await domainExists(msg.domain);
      sendResponse({ exists });
    })();
    return true;
  }
});
