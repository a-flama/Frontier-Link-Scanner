document.addEventListener('DOMContentLoaded', async () => {
  const keyInput = document.getElementById('vt-key');
  const saveBtn = document.getElementById('save-btn');
  const status = document.getElementById('status');

  const data = await chrome.storage.local.get(['vt_api_key']);
  if (data.vt_api_key) keyInput.value = data.vt_api_key;

  saveBtn.addEventListener('click', async () => {
    const key = keyInput.value.trim();
    await chrome.storage.local.set({ vt_api_key: key });
    status.textContent = "Key saved successfully!";
    setTimeout(() => { status.textContent = ""; }, 2000);
  });
});