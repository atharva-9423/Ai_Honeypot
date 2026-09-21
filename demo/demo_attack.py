"""Controlled demo attack against the VIRTUAL environment only. Never auto-run by the app.

Usage:
    python demo/demo_attack.py [BASE_URL] [SESSION_ID]
    python demo/demo_attack.py SES-XXXXXX   (drive that browser tab live)
    python demo/demo_attack.py http://127.0.0.1:8000
    SENTINEL_BASE=http://127.0.0.1:8000 python demo/demo_attack.py

With no BASE_URL the script auto-detects a running server on ports
8000/8001/8002/8003, so it works whichever port you started with:
    python -m uvicorn backend.main:app --port 8000
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

BASE = None
CANDIDATE_PORTS = (8000, 8001, 8002, 8003)


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


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def main():
    global BASE
    raw = sys.argv[1] if len(sys.argv) > 1 else ""
    if raw.startswith("http"):
        BASE = resolve_base(raw)
        want_sid = sys.argv[2] if len(sys.argv) > 2 else None
    elif raw:
        BASE = resolve_base(os.environ.get("SENTINEL_BASE") or "")
        want_sid = raw
    else:
        BASE = resolve_base(os.environ.get("SENTINEL_BASE") or "")
        want_sid = None
    try:
        health = call("GET", "/api/health")
    except Exception:
        print(f"ERROR: cannot reach SENTINEL at {BASE}.")
        print("Start the server first with:  python -m uvicorn backend.main:app --port 8000")
        print(f"Then open the app at {BASE} and re-run this script.")
        sys.exit(1)
    print(f"server ok: {health}")

    # Judge journey: inspect company data, hunt credentials, steal decoys.
    COMMANDS = ["ls /srv/meridian",
                "cat /srv/meridian/docs/onboarding.txt",
                "cat /srv/meridian/customers.csv",
                "find / -name credentials.txt",
                "cat /srv/meridian/api/config.json",
                "cat /srv/meridian/api/.env",
                "cat /backup/cloud_credentials.txt",
                "ls /opt/backup",
                "cat /opt/backup/credentials.txt"]

    if want_sid:
        try:
            call("GET", f"/api/sessions/{want_sid}")
            sid = want_sid
            print(f"driving existing session — watch it live at "
                  f"{BASE}/terminal.html?session={sid}")
        except urllib.error.HTTPError:
            print(f"ERROR: session {want_sid} unknown on {BASE} (server restarted?).")
            sys.exit(1)
    else:
        s = call("POST", "/api/sessions")
        sid = s["session_id"]
        print(f"session: {sid}  (watch it live at {BASE}/terminal.html?session={sid})")
        print(f"(commands below also stream live into an open")
        print(f"terminal.html tab attached to this session via remote-exec)")
    for c in COMMANDS:
        r = call("POST", f"/api/sessions/{sid}/remote-exec", {"command": c})
        print(f"\n$ {c}\n{r['output'][:600]}")
        for e in r.get("events", []):
            print(f"  [event] {e['event_type']} ({e['severity']})")
        for d in r.get("deception", []):
            print(f"  [deception] {d['action']} -> {d['target']}")
        time.sleep(0.2)

    intel = call("GET", f"/api/sessions/{sid}/intelligence")
    print("\nSession threat:", intel["threat"])
    dash = call("GET", "/api/dashboard")
    print("Dashboard now shows:", dash["counts"])
    assert dash["counts"]["events"] > 0, "expected events on the dashboard"
    print(f"\nDone. Open {BASE} -> Overview to see this session, "
          f"or replay it at {BASE}/terminal.html?session={sid}.")


if __name__ == "__main__":
    main()
