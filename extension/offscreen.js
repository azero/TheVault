// Offscreen document: the only way a service worker can write to the clipboard.
chrome.runtime.onMessage.addListener((m) => {
  if (m?.target !== 'offscreen' || m.type !== 'copy') return
  const t = document.getElementById('t')
  t.value = m.text || ' '
  t.select()
  document.execCommand('copy')
  if (!m.text) t.value = ''
})
