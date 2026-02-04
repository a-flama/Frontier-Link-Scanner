async function vtUrlCheck(url) {
  const { vt_api_key } = await chrome.storage.local.get(["vt_api_key"]);
  if (!vt_api_key) return { error: "no_key" };

  try {
    const id = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": vt_api_key }
    });

    if (r.status === 404) return { unknown: true };
    const j = await r.json();
    const stats = j?.data?.attributes?.last_analysis_stats || {};
    return { malicious: (stats.malicious || 0) > 0, stats };
  } catch (e) { return { error: String(e) }; }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "vtCheck") {
    vtUrlCheck(msg.url).then(sendResponse);
    return true; 
  }
});