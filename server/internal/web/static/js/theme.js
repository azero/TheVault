// Applies the saved theme before the first paint (so there is no flash). Loaded synchronously from <head>.
try {
  const t = localStorage.getItem('vault-theme')
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t
} catch { /* storage blocked: follow the system setting */ }
