"""Demo attack 2: drives Discovery, Persistence Attempt and Data Discovery.

Runs against the VIRTUAL environment via the remote-exec endpoint, so every
command appears LIVE in an open terminal.html session for the same session id.
Tip: open http://127.0.0.1:8000/terminal.html first, copy its session id from
the top bar, and pass it as the second argument — then watch it type itself.

Usage:
    python demo/demo_attack_progression.py [BASE_URL] [SESSION_ID]
    python demo/demo_attack_progression.py http://127.0.0.1:8000 SES-XXXXXX
    python demo/demo_attack_progression.py SES-XXXXXX   (auto-detect server)

Never auto-run by the app.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

BASE = None
CANDIDATE_PORTS = (8000, 8001, 8002, 8003)
_raw_arg = sys.argv[1] if len(sys.argv) > 1 else ""
if _raw_arg.startswith("http"):
    _EXPLICIT_BASE = _raw_arg
    WANT_SID = sys.argv[2] if len(sys.argv) > 2 else None
elif _raw_arg:
    _EXPLICIT_BASE = os.environ.get("SENTINEL_BASE") or ""
    WANT_SID = _raw_arg
else:
    _EXPLICIT_BASE = os.environ.get("SENTINEL_BASE") or ""
    WANT_SID = sys.argv[2] if len(sys.argv) > 2 else None


def _probe(base):
    req = urllib.request.Request(base + "/api/health", method="GET")
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.loads(r.read().decode())


def resolve_base(explicit):
    if explicit:
        return explicit.rstrip("/")
    for port in CANDIDATE_PORTS:
        base = f"http://127.0.0.1:{port}"
        try:
            _probe(base)
            print(f"auto-detected server at {base}")
            return base
        except Exception:
            continue
    return "http://127.0.0.1:8000"

STAGES = [
    ("Discovery", [
        "whoami",
        "id",
        "uname -a",
        "ifconfig",
    ]),
    ("Persistence Attempt", [
        "crontab -l",
        "mkdir -p ~/.ssh",
        "echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsYntH3t1c >> ~/.ssh/authorized_keys",
        "systemctl enable meridian-api",
        "systemctl status meridian-api",
    ]),
    ("Data Discovery", [
        "cat /srv/meridian/customers.csv",
        "grep -i customer /srv/meridian/customers.csv",
        "cat /var/log/syslog",
        "cat /etc/passwd",
    ]),
]


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def main():
    global BASE
    BASE = resolve_base(_EXPLICIT_BASE)
    try:
        call("GET", "/api/health")
    except Exception:
        print(f"ERROR: cannot reach SENTINEL at {BASE}.")
        print("Start the server first with:  python -m uvicorn backend.main:app --port 8000")
        sys.exit(1)

    if WANT_SID:
        try:
            call("GET", f"/api/sessions/{WANT_SID}")
            sid = WANT_SID
            print(f"driving existing session (watch it live in the browser): {sid}")
        except urllib.error.HTTPError:
            print(f"ERROR: session {WANT_SID} unknown on {BASE} (server restarted?).")
            sys.exit(1)
    else:
        sid = call("POST", "/api/sessions")["session_id"]
        print(f"session: {sid}  (open {BASE}/terminal.html to watch — "
              f"a new browser tab gets its own session)")

    for stage, commands in STAGES:
        print(f"\n===== {stage} =====")
        for c in commands:
            r = call("POST", f"/api/sessions/{sid}/remote-exec", {"command": c})
            print(f"\n$ {c}\n{r['output'][:500]}")
            for e in r.get("events", []):
                print(f"  [event] {e['event_type']} ({e['severity']}) -> {e['stage']}")
            time.sleep(0.4)

    intel = call("GET", f"/api/sessions/{sid}/intelligence")
    reached = {p["stage"] for p in intel["progression"] if p["reached"]}
    print("\nAttack progression reached:", sorted(reached))
    for want in ["Discovery", "Persistence Attempt", "Data Discovery"]:
        assert want in reached, f"stage not reached: {want}"
    print(f"\nDone. Overview: {BASE}  |  Replay: {BASE}/terminal.html?session={sid}")


if __name__ == "__main__":
    main()
