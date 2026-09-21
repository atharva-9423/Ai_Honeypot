async function loadReport() {
  let sid = '';
  try {
    const d = await api('/api/sessions');
    const act = (d.sessions || []).filter((s) => s.status === 'active')
      .sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    if (act.length) { sid = act[0].session_id; store.sid = sid; }
  } catch {}
  if (!sid) sid = store.sid;
  const box = document.getElementById('report');
  document.getElementById('rep-sid').textContent = sid || '—';
  if (!sid) {
    box.innerHTML = `<div class="empty"><h4>No session selected</h4><p>Reports are generated only from real session data — interact via the terminal at <code>/terminal.html</code>.</p></div>`;
    return;
  }
  let rep;
  try { rep = await api(`/api/sessions/${sid}/report`); }
  catch { box.innerHTML = `<div class="empty"><h4>Session not found</h4></div>`; return; }
  window._report = rep;
  box.innerHTML = `
    <div class="card"><h3>Executive summary</h3><p>${esc(rep.executive_summary)}</p>
      <p class="meta">Generated ${new Date(rep.generated_at * 1000).toLocaleString()} · ${esc(rep.title)}</p></div>
    <h2 class="section-title">Attack timeline</h2>
    <div class="card">${rep.timeline.length ? `<ul class="timeline">${rep.timeline.map((t) => `<li><time>${fmtTime(t.timestamp)}</time><div><span class="badge ${esc(t.severity)}">${esc(t.severity)}</span> ${esc(t.event)}<div class="meta">${esc(t.stage || '')}</div><code>${esc(t.evidence || '')}</code></div></li>`).join('')}</ul>` : '<div class="empty"><h4>Empty timeline</h4><p>No events recorded in this session.</p></div>'}</div>
    <h2 class="section-title">MITRE ATT&amp;CK</h2>
    <div class="card">${rep.mitre.length ? rep.mitre.map((m) => `<div class="event-row"><div><strong>${esc(m.id)}</strong> — ${esc(m.name)}</div></div>`).join('') : '<div class="empty"><h4>No mappings</h4></div>'}</div>
    <h2 class="section-title">Deception actions</h2>
    <div class="card">${rep.deception_actions.length ? rep.deception_actions.map((d) => `<div class="event-row"><div><strong>${esc(d.action)}</strong> → <code>${esc(d.target)}</code><div class="meta">${esc(d.reason || '')}</div></div></div>`).join('') : '<div class="empty"><h4>No deception deployed</h4></div>'}</div>
    <h2 class="section-title">Raw JSON</h2>
    <pre class="report">${esc(JSON.stringify(rep, null, 2)).slice(0, 8000)}</pre>`;
}
document.addEventListener('DOMContentLoaded', () => {
  loadReport();
  document.getElementById('btn-json').addEventListener('click', () => {
    if (!window._report) return toast('Nothing to export yet.');
    const blob = new Blob([JSON.stringify(window._report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sentinel-report-${store.sid || 'session'}.json`;
    a.click();
  });
  document.getElementById('btn-pdf').addEventListener('click', () => window.print());
});
