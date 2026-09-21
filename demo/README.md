# SENTINEL demo (manual, never auto-executed)

The app starts with **zero demo data**. To rehearse the 5-minute judge flow:

```bash
uvicorn backend.main:app --port 8000
python demo/demo_attack.py
python demo/demo_attack_progression.py
```

Then open `http://127.0.0.1:8000` and verify:
1. Overview shows real counts from the demo sessions only.
2. Intelligence shows Credential Discovery + honeytoken event.
3. `/opt/backup/credentials.txt` decoy appeared (adaptive deception).
4. Report exports JSON / Print-to-PDF.

## Watching commands run live in the browser terminal

Both scripts use the `remote-exec` endpoint, so their commands stream into
`terminal.html` in real time. To watch a specific browser tab type itself:

1. Open `http://127.0.0.1:8000/terminal.html` and copy the session id
   from the top bar (e.g. `SES-XXXXXX`).
2. Run the stages script against that exact session:

```bash
python demo/demo_attack_progression.py http://127.0.0.1:8000 SES-XXXXXX
```

The browser terminal will print each command and its output as it runs,
and the Overview attack feed, progression, and Intelligence update alongside.

Shortcut — drive the tab's session directly (both scripts accept it):

```bash
python demo/demo_attack.py SES-XXXXXX
```

or open the replay link the script prints at the end:

```bash
http://127.0.0.1:8000/terminal.html?session=SES-XXXXXX
```

Any tab opened with `?session=` attaches to that session: past commands
replay instantly and new script-driven commands stream in live.

## What each script covers

- `demo_attack.py` — Reconnaissance → Discovery → Credential Discovery,
  honeytoken access, adaptive decoy deployment.
- `demo_attack_progression.py` — Discovery (whoami/id/uname/ifconfig),
  Persistence Attempt (crontab, SSH key plant, systemctl), Data Discovery
  (customer export, log and passwd reads). Asserts all three stages light up.
