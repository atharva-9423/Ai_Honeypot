/* Standalone attacker-facing terminal. No defender intel here by design —
   observation lives on the dashboard (/index.html). Shares api.js helpers. */
let SID = store.sid;
let CWD = '/home/sentinel';

async function ensureSession() {
  // ?session=SES-XXXX lets a demo script drive THIS tab live: the tab
  // attaches to that session instead of creating its own.
  const qs = new URLSearchParams(location.search).get('session');
  if (qs) {
    try { await api(`/api/sessions/${qs}`); SID = qs; store.sid = SID; return SID; }
    catch { /* unknown/closed — fall through to stored/new */ }
  }
  if (SID) {
    try { await api(`/api/sessions/${SID}`); return SID; } catch { /* recreate */ }
  }
  const s = await api('/api/sessions', { method: 'POST' });
  SID = s.session_id; store.sid = SID;
  return SID;
}

function printLine(html) {
  const body = document.getElementById('term-body');
  const div = document.createElement('div');
  div.className = 'term-line';
  div.innerHTML = html;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
}

function promptHtml() {
  return `<span class="prompt">sentinel@server01:${esc(CWD)}$</span>`;
}

async function postExec(raw) {
  return api(`/api/sessions/${SID}/exec`, { method: 'POST', body: JSON.stringify({ command: raw }) });
}

let termWs = null;
function subscribeWs() {
  if (termWs) { try { termWs.onclose = null; termWs.close(); } catch {} termWs = null; }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  let ws;
  try { ws = new WebSocket(`${proto}://${location.host}/ws/session/${SID}`); }
  catch { return; }
  termWs = ws;
  ws.onmessage = (m) => {
    let msg;
    try { msg = JSON.parse(m.data); } catch { return; }
    if (!msg || msg.kind !== 'exec' || !msg.remote) return; // own keys already rendered
    printLine(`${promptHtml()} ${esc(msg.command || '')}`);
    CWD = msg.cwd || CWD;
    if (msg.clear) document.getElementById('term-body').innerHTML = '';
    if (msg.output) printLine(`<div class="term-out">${esc(msg.output)}</div>`);
    if (msg.suggestion) printLine(`<div class="term-out" style="color:#98A2B3">Did you mean '${esc(msg.suggestion)}'? (not executed)</div>`);
  };
  ws.onclose = () => { if (termWs === ws) setTimeout(subscribeWs, 3000); };
}

async function runCommand(raw) {
  printLine(`${promptHtml()} ${esc(raw)}`);
  const fail = (msg) => {
    printLine(`<span class="term-err">request failed: ${esc(msg)}</span>`);
  };
  let res;
  try {
    res = await postExec(raw);
  } catch (e) {
    // Self-heal: the server forgets sessions on restart. If ours is gone
    // (or closed), silently establish a fresh one and retry the command once.
    if (/Unknown session|Session is closed/.test(e.message || '')) {
      try {
        const s = await api('/api/sessions', { method: 'POST' });
        SID = s.session_id; store.sid = SID; CWD = '/home/sentinel';
        document.getElementById('conn').textContent = `Connected · ${SID}`;
        printLine(`<div class="term-out" style="color:#98A2B3">Server had no such session (restart?) — new session ${esc(SID)} established, retrying.</div>`);
        res = await postExec(raw);
      } catch (e2) { fail(e2.message); return; }
    } else { fail(e.message); return; }
  }
  CWD = res.cwd || CWD;
  if (res.clear) document.getElementById('term-body').innerHTML = '';
  if (res.output) printLine(`<div class="term-out">${esc(res.output)}</div>`);
  if (res.suggestion) printLine(`<div class="term-out" style="color:#98A2B3">Did you mean '${esc(res.suggestion)}'? (not executed)</div>`);
  if (res.exit) {
    printLine(`<div class="term-out">Session closed. Start a new one to continue.</div>`);
    store.clear();
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  const input = document.getElementById('term-input');
  try {
    await ensureSession();
    document.getElementById('conn').textContent = `Connected · ${SID}`;
    subscribeWs();
    printLine(`<div class="term-out">Last login: Mon Jan 12 09:14:02 from 10.0.0.8</div>`);
    // Replay the persisted transcript so navigation/reload never loses the session.
    try {
      const t = await api(`/api/sessions/${SID}/transcript`);
      for (const e of t.transcript || []) {
        if (e.clear) document.getElementById('term-body').innerHTML = '';
        printLine(`<span class="prompt">sentinel@server01:${esc(e.cwd || '/home/sentinel')}$</span> ${esc(e.command || '')}`);
        if (e.output) printLine(`<div class="term-out">${esc(e.output)}</div>`);
      }
      if (t.cwd) CWD = t.cwd;
    } catch { /* transcript unavailable — continue with a fresh screen */ }
  } catch (e) {
    printLine(`<span class="term-err">Backend unreachable. Start it with: uvicorn backend.main:app --reload</span>`);
    return;
  }
  input.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
      const v = input.value;
      input.value = '';
      await runCommand(v);
      document.getElementById('term-body').scrollTop = 1e9;
    }
  });
  document.getElementById('term-body').addEventListener('click', () => input.focus());
  input.focus();
  document.getElementById('btn-reset').addEventListener('click', () => {
    document.getElementById('reset-modal').classList.add('open');
  });
  document.getElementById('btn-cancel-reset').addEventListener('click', () => {
    document.getElementById('reset-modal').classList.remove('open');
  });
  document.getElementById('btn-confirm-reset').addEventListener('click', async () => {
    document.getElementById('reset-modal').classList.remove('open');
    await api(`/api/sessions/${SID}/reset`, { method: 'POST' });
    document.getElementById('term-body').innerHTML = '';
    CWD = '/home/sentinel';
    printLine(`<div class="term-out">Session reset.</div>`);
  });
  document.getElementById('btn-new').addEventListener('click', async () => {
    const s = await api('/api/sessions', { method: 'POST' });
    SID = s.session_id; store.sid = SID; CWD = '/home/sentinel';
    document.getElementById('term-body').innerHTML = '';
    document.getElementById('conn').textContent = `Connected · ${SID}`;
    subscribeWs();
    printLine(`<div class="term-out">Last login: Mon Jan 12 09:14:02 from 10.0.0.8</div>`);
  });
});
