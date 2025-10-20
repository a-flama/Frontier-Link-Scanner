const input = document.getElementById('vtkey');
const saveBtn = document.getElementById('save');

async function load() {
  const s = await chrome.storage.local.get(['vt_api_key','vt_enabled']);
  input.value = s.vt_api_key || '';
}
saveBtn.addEventListener('click', async () => {
  const key = input.value.trim();
  await chrome.storage.local.set({ vt_api_key: key });
  alert('Saved (kept locally)');
});
load();

