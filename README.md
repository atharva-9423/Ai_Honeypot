# SENTINEL — AI-Adaptive Cyber Deception & Threat Intelligence Platform

> Don't fight the attacker. Make them reveal more.

## Quick start

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000`. Counters start at **0** — no demo data.

## Demo story (for judges)

- **Terminal (attack surface):** `http://127.0.0.1:8000/terminal.html` —
  looks like the server of *Meridian Logistics* (fictional company) with
  inspectable confidential data under `/srv/meridian` (customer export,
  finance sheet, API config). Everything is synthetic; the AWS keys are
  AWS's officially documented example keys — realistic but guaranteed fake.
- **Real System tab:** `/real.html` — the fictional production truth:
  company profile, credentials, documents, logs, services. Judges compare
  anything stolen from the honeypot against these values — they never match.
- **AI Honeypot replica:** every session builds an exact-structure mirror of
  the real layout whose file contents are generated per session — by Groq
  (`gpt-oss-120b`) when `GROQ_API_KEY` is set, validated deterministic
  templates otherwise. The validator guarantees no decoy ever equals a real
  secret. The system also learns: sustained interest in one area (finance,
  api, docs…) automatically plants follow-up decoys there (max 3/session),
  and every attack, observation, interest and expansion streams into the
  Overview attack feed and Intelligence pages.

## Groq AI interpretation (optional)

```bash
cp .env.example .env   # then set GROQ_API_KEY
pip install -r requirements-test.txt
python -m pytest backend/tests/ -q
```

Without a key the terminal works fully on the deterministic engine;
unknown commands return `command not found`. With a key, commands like
`tail`, `head`, `stat`, `df` or typos like `lss` are interpreted by Groq
into safe virtual-filesystem operations. Groq never executes anything —
it returns JSON, the backend validates it with Pydantic and the virtual
state engine stays authoritative.

## Safety

- No `subprocess` / host shell execution anywhere in the request path.
- Virtual in-memory filesystem per session; nothing touches the host FS.
- No external connections, scans, or counter-attacks.
- All decoy secrets labelled `SYNTHETIC DECOY`.
- Deterministic rule engine is authoritative; optional LLM (`SENTINEL_LLM_ENDPOINT`)
  output is validated JSON and never executed.

## Structure

- `backend/main.py` — FastAPI app, REST + WebSocket, static frontend serving
- `backend/engine/` — virtual_fs, command_parser, state_manager, behavior_engine, deception_engine, honeytokens
- `backend/ai/` — deterministic analyzer (+ optional LLM hook), prompts, schemas
- `backend/security/guardrails.py` — input sanitization, policy engine, output validation
- `frontend/` — vanilla HTML/CSS/JS (index, session, intelligence, reports, system)
- `demo/` — manual-only demo script (never auto-run)
