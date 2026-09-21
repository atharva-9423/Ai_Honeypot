async function pickLatestActiveSid() {
  try {
    const d = await api('/api/sessions');
    const act = (d.sessions || []).filter((s) => s.status === 'active')
      .sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    return act.length ? act[0].session_id : '';
  } catch { return ''; }
}
async function loadIntel() {
  // Follow the action: always show the newest active session so the page
  // tracks live attacks (terminal, demo scripts) instead of a stale id.
  const sid = await pickLatestActiveSid();
  const box = document.getElementById('intel');
  if (!sid) {
    box.innerHTML = `<div class="empty"><h4>No session selected</h4><p>Interact via the terminal — intelligence is generated only from real interaction.</p></div>`;
    document.getElementById('intel-sid').textContent = '—';
    return;
  }
  store.sid = sid;
  document.getElementById('intel-sid').textContent = sid;
  let intel;
  try { intel = await api(`/api/sessions/${sid}/intelligence`); }
  catch { box.innerHTML = `<div class="empty"><h4>Session not found</h4><p>It may have been cleared. Start a new session.</p></div>`; return; }
  const ai = intel.ai_analysis || {};
  box.innerHTML = `
    <div class="grid grid-2">
      <div class="card"><h3>Session information</h3>
        <dl class="kv">
          <dt>Session ID</dt><dd>${esc(sid)}</dd>
          <dt>Commands</dt><dd>${intel.session.commands}</dd>
          <dt>Events</dt><dd>${intel.session.event_count}</dd>
          <dt>Duration</dt><dd>${Math.round(intel.session.duration_sec)}s</dd>
          <dt>Threat</dt><dd><span class="badge ${esc((intel.threat || 'none').toLowerCase())}">${esc(intel.threat)}</span></dd>
        </dl></div>
      <div class="card"><h3>Behavioral profile</h3>
        <p><strong>${esc(intel.actor.label)}</strong> · ${intel.actor.confidence}% confidence</p>
        <p class="meta">Observed: ${intel.actor.behaviors.length ? esc(intel.actor.behaviors.join(', ')) : 'no staged behavior yet'}</p>
        <h3 style="margin-top:14px">Attack progression</h3>
        ${intel.progression.map((p) => `<div class="stage ${p.reached ? 'reached' : ''}"><span class="node">${p.reached ? '✓' : '·'}</span><span>${esc(p.stage)}</span></div>`).join('')}
      </div>
    </div>
    <h2 class="section-title">MITRE ATT&amp;CK mapping</h2>
    <div class="card">${intel.mitre.length ? `<table class="clean"><tr><th>ID</th><th>Technique</th></tr>${intel.mitre.map((m) => `<tr><td>${esc(m.id)}</td><td>${esc(m.name)}</td></tr>`).join('')}</table>` : '<div class="empty"><h4>No techniques mapped</h4><p>Mappings appear only when a behavioral rule fires with evidence.</p></div>'}</div>
    <h2 class="section-title">Indicators</h2>
    <div class="card">${intel.indicators.length ? `<table class="clean"><tr><th>Type</th><th>Value</th></tr>${intel.indicators.slice(0, 50).map((i) => `<tr><td>${esc(i.type)}</td><td><code>${esc(i.value)}</code></td></tr>`).join('')}</table>` : '<div class="empty"><h4>No indicators collected</h4></div>'}</div>
    <h2 class="section-title">Honeytoken events</h2>
    <div class="card">${intel.honeytokens.length ? intel.honeytokens.map((h) => `<div class="event-row"><span class="badge high">high</span><div>${esc(h.type)}<div class="meta">${fmtTime(h.timestamp)} · ${esc(h.command || '')}</div></div></div>`).join('') : '<div class="empty"><h4>No honeytoken access</h4></div>'}</div>
    <h2 class="section-title">Behavioral assessment</h2>
    <div class="card">
      <dl class="kv">
        <dt>Behavior</dt><dd>${esc(ai.behavior || '—')}</dd>
        <dt>Confidence</dt><dd>${esc(ai.confidence ?? '—')}</dd>
        <dt>Hypothesis</dt><dd>${esc(ai.intent_hypothesis || '—')}</dd>
        <dt>Severity</dt><dd>${esc(ai.severity || '—')}</dd>
      </dl>
      <p class="meta">Evidence</p>
      <ul>${(ai.evidence || []).map((e) => `<li><code>${esc(e)}</code></li>`).join('') || '<li>—</li>'}</ul>
      <p>${esc(ai.recommended_action || '')}</p>
    </div>
    <h2 class="section-title">What the system learned</h2>
    <div class="grid grid-2">
      <div class="card"><h3>Attacker interests</h3>
        ${intel.interests && Object.keys(intel.interests).length
          ? `<dl class="kv">${Object.entries(intel.interests).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v} accesses</dd>`).join('')}</dl><p class="meta">Sustained interest (2+ accesses) triggers new decoys in that area.</p>`
          : '<div class="empty"><h4>No focused interest yet</h4></div>'}</div>
      <div class="card"><h3>Replica manifest</h3>
        <dl class="kv">
          <dt>Source</dt><dd>${esc((intel.decoy_manifest || {}).source || '—')}</dd>
          <dt>Model</dt><dd>${esc((intel.decoy_manifest || {}).model || '—')}</dd>
          <dt>Files</dt><dd>${((intel.decoy_manifest || {}).files || []).length}</dd>
        </dl>
        <p class="meta">${esc((intel.decoy_manifest || {}).note || '')}</p></div>
    </div>
    <h2 class="section-title">Adaptive deception actions</h2>
    <div class="card">${(intel.deception_actions || []).length ? intel.deception_actions.map((d) => `<div class="event-row"><div><strong>${esc(d.action)}</strong> → <code>${esc(d.target || '')}</code><div class="meta">${fmtTime(d.timestamp)} · ${esc(d.reason || '')}</div></div></div>`).join('') : '<div class="empty"><h4>No deception deployed</h4><p>Decoys appear here once suspicious behavior is observed.</p></div>'}</div>`;
}
document.addEventListener('DOMContentLoaded', () => {
  loadIntel();
  setInterval(loadIntel, 3000);
});
