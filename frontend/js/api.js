async function api(path, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  let res;
  try {
    res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
      signal: ctrl.signal,
    });
  } catch (e) {
    throw new Error(`Backend unreachable or timed out (${e.name === 'AbortError' ? '10s timeout' : e.message}). Start it with: uvicorn backend.main:app --port 8000`);
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const t = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${t.slice(0, 300)}`);
  }
  return res.json();
}
const store = {
  get sid() { return localStorage.getItem('sentinel_session') || ''; },
  set sid(v) { if (v) localStorage.setItem('sentinel_session', v); },
  clear() { localStorage.removeItem('sentinel_session'); },
};
function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function toast(msg) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 3200);
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
/* Collapsible "AI Honeypot" sidebar group (no-op on pages without one). */
document.addEventListener('DOMContentLoaded', () => {
  const t = document.getElementById('hp-toggle');
  const s = document.getElementById('hp-sub');
  if (!t || !s) return;
  const apply = (open) => {
    s.classList.toggle('hidden', !open);
    t.classList.toggle('closed', !open);
    t.setAttribute('aria-expanded', String(open));
  };
  let open = true;
  try { const v = localStorage.getItem('sentinel_hp'); if (v !== null) open = v === '1'; } catch {}
  if (s.querySelector('.nav-link.active')) open = true;
  apply(open);
  t.addEventListener('click', () => {
    open = !open;
    try { localStorage.setItem('sentinel_hp', open ? '1' : '0'); } catch {}
    apply(open);
  });
});
