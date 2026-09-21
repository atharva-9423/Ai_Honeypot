async function loadDashboard() {
  let data;
  try {
    data = await api('/api/dashboard');
  } catch (e) {
    const banner = document.getElementById('conn-banner');
    if (banner) {
      banner.style.display = 'block';
      banner.innerHTML = `Backend unreachable. Start it with <code>uvicorn backend.main:app --reload</code>, then open this page via <code>http://127.0.0.1:8000</code> (not as a file).`;
    }
    return;
  }
  const banner = document.getElementById('conn-banner');
  if (banner) banner.style.display = 'none';
  const c = data.counts || {};
  set('m-sessions', c.active_sessions ?? 0);
  const threat = data.threat || 'None';
  const threatEl = document.getElementById('m-threat');
  if (threatEl) threatEl.innerHTML = threat === 'None' ? '—' : `<span class="badge ${threat.toLowerCase()}">${esc(threat)}</span>`;
  set('m-events', c.events ?? 0);
  set('m-honey', c.honeytokens_triggered ?? 0);
  renderProgression(data.progression || []);
  renderFeed(data.recent_commands || []);
  renderRecent(data.recent_events || []);
  renderSessions(data.active || []);
}
function set(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }
function renderProgression(prog) {
  const box = document.getElementById('progression');
  if (!box) return;
  if (!prog.length) {
    box.innerHTML = `<p class="meta">No stages observed yet.</p>`;
    return;
  }
  box.innerHTML = prog.map((p) => `
    <div class="stage ${p.reached ? 'reached' : ''}">
      <span class="node">${p.reached ? '✓' : '·'}</span>
      <span>${esc(p.stage)}${p.evidence_count ? ` <span class="meta">(${p.evidence_count})</span>` : ''}</span>
    </div>`).join('');
}
function renderFeed(commands) {
  const box = document.getElementById('attack-feed');
  if (!box) return;
  if (!commands.length) {
    box.innerHTML = `<div class="empty"><h4>No attacks observed yet</h4><p>Commands typed in <code>/terminal.html</code> appear here live.</p></div>`;
    return;
  }
  box.innerHTML = commands.map((c) => `
    <div class="event-row"><time>${fmtTime(c.ts)}</time>
      <div><code>${esc(c.command || '')}</code>
      <div class="meta">${esc(c.session_id || '')}${(c.events || []).length ? ` → ${(c.events || []).map((e) => `<span class="badge low">${esc(e)}</span>`).join(' ')}` : ' → <span class="meta">no rule fired</span>'}</div></div>
    </div>`).join('');
}
function renderRecent(events) {
  const box = document.getElementById('recent');
  if (!box) return;
  if (!events.length) {
    box.innerHTML = `<div class="empty"><h4>No security events yet</h4><p>Interact with the deception environment to generate telemetry.</p></div>`;
    return;
  }
  box.innerHTML = events.map((e) => `
    <div class="event-row">
      <span class="badge ${esc(e.severity || 'low')}">${esc(e.severity || '')}</span>
      <div><div>${esc(e.type || '')} <span class="meta">· ${esc(e.session_id || '')} · ${fmtTime(e.timestamp)}</span></div>
      <code>${esc(e.command || '')}</code></div>
    </div>`).join('');
}
function renderSessions(sessions) {
  const box = document.getElementById('sessions');
  if (!box) return;
  if (!sessions.length) {
    box.innerHTML = `<div class="empty"><h4>No active sessions</h4><p>The deception environment is ready for interaction.</p><p class="meta">Interact via the terminal at <code>/terminal.html</code>.</p></div>`;
    return;
  }
  box.innerHTML = sessions.map((s) => `
    <div class="event-row"><div><strong>${esc(s.session_id)}</strong>
    <div class="meta">${s.commands ?? 0} commands · ${esc(s.status || '')} · stage: ${esc(s.stage || '—')} · threat: ${esc(s.threat || 'None')}</div>
    ${(s.interests && Object.keys(s.interests).length) ? `<div class="meta">interests: ${esc(Object.entries(s.interests).map(([k, v]) => `${k}×${v}`).join(', '))}</div>` : ''}</div></div>`).join('');
}
document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();
  const wsProto = location.protocol === 'https:' ? 'wss' : 'ws';
  try {
    const ws = new WebSocket(`${wsProto}://${location.host}/ws/dashboard`);
    ws.onmessage = (m) => {
      try {
        const msg = JSON.parse(m.data);
        if (msg.kind === 'event_batch' || msg.kind === 'session_reset' || msg.kind === 'session_created') loadDashboard();
      } catch {}
    };
  } catch {}
  setInterval(loadDashboard, 5000);
});
