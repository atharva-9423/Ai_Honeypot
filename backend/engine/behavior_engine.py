"""Deterministic behavioral rule engine + MITRE mapping + attack stages."""
from __future__ import annotations
import re

CRED_KEYWORDS = ["credential", "credentials", "password", "passwd", "secret",
                 ".key", "cloud_credentials", "aws", "access_key", "token",
                 ".env", "id_rsa", ".pem", "config.json"]
PRIV_PATHS = ["/etc/shadow", "/etc/sudoers", "/etc/passwd"]
STAGE_ORDER = ["Reconnaissance", "Discovery", "Credential Discovery",
               "Persistence Attempt", "Data Discovery"]

MITRE = {
    "recon": [{"id": "T1083", "name": "File and Directory Discovery"}],
    "discovery": [{"id": "T1082", "name": "System Information Discovery"},
                  {"id": "T1016", "name": "System Network Configuration Discovery"}],
    "credential_discovery": [{"id": "T1552", "name": "Unsecured Credentials"}],
    "privilege_escalation": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism"}],
    "data_discovery": [{"id": "T1005", "name": "Data from Local System"}],
    "persistence": [{"id": "T1053", "name": "Scheduled Task/Job"}],
    "honeytoken": [{"id": "T1552", "name": "Unsecured Credentials"}],
}


def classify_actor(history: list[str]) -> tuple[str, int]:
    """Returns (label, confidence 0-100)."""
    n = len(history)
    if n == 0:
        return "Unknown", 0
    auto_markers = sum(1 for c in history if re.search(r"(;|&&|\|\||for |while |curl|wget|nmap)", c))
    if auto_markers >= 3:
        return "Automated", min(90, 60 + auto_markers * 10)
    if n >= 4:
        return "Human-like", min(92, 55 + n * 5)
    return "Unknown", 40 + n * 5


def analyze_command(command: str, accessed_paths: list[str]) -> list[dict]:
    """Pure function: command + accessed paths -> candidate events (no I/O)."""
    events: list[dict] = []
    low = command.lower().strip()
    base = low.split()[0] if low else ""

    def ev(event_type, severity, stage, detail, mitre_key):
        events.append({"event_type": event_type, "severity": severity,
                       "stage": stage, "detail": detail,
                       "evidence": [command], "mitre": MITRE[mitre_key]})

    # honeytoken (checked also in main flow, but keep here for completeness)
    for p in accessed_paths or []:
        from .honeytokens import is_honeytoken
        if is_honeytoken(p):
            ev("honeytoken_accessed", "high", "Credential Discovery",
               f"Honeytoken accessed: {p}", "honeytoken")

    # credential discovery
    if any(k in low for k in CRED_KEYWORDS) or \
       any(any(k in (p or "").lower() for k in CRED_KEYWORDS) for p in (accessed_paths or [])):
        if base in ("find", "grep", "cat", "ls", "touch", "echo") or "cat" in low or "find" in low or "grep" in low:
            ev("credential_discovery", "high", "Credential Discovery",
               "Credential-related file search or access observed.", "credential_discovery")

    # privilege escalation
    if base in ("sudo", "su") or "chmod" in low or "chown" in low or \
       any(pp in low for pp in ["/etc/shadow", "/etc/sudoers"]):
        ev("privilege_escalation_attempt", "high", "Persistence Attempt",
           "Privilege-escalation related activity observed.", "privilege_escalation")

    # persistence
    if "crontab" in low or "systemctl" in low or ".ssh/authorized_keys" in low:
        ev("persistence_attempt", "medium", "Persistence Attempt",
           "Possible persistence mechanism touched.", "persistence")

    # recon: enumeration commands
    if base in ("find",) or (base == "ls" and ("/" in low or "-r" in low or "-la" in low)) or \
       (base == "ls" and len(low.split()) == 1):
        ev("reconnaissance", "low" if base == "ls" and low.strip() == "ls" else "medium",
           "Reconnaissance", "File/directory enumeration observed.", "recon")

    # discovery: system/network enumeration
    if base in ("whoami", "id", "uname", "ps", "env", "hostname", "ifconfig", "ip", "netstat"):
        ev("discovery", "low", "Discovery", f"System enumeration via `{base}`.", "discovery")

    # data discovery
    if base == "grep" or (base == "cat" and any(x in low for x in ["/var/log", "/etc/passwd", "database", "customer", ".csv"])):
        # avoid double counting pure credential greps — still fine to add data discovery if log/db touched
        if any(x in low for x in ["/var/log", "/etc/passwd", "database", "customer", ".csv", ".db"]):
            ev("data_discovery", "medium", "Data Discovery",
               "Sensitive-data location enumerated or read.", "data_discovery")

    return events


def progression_from_events(events: list[dict]) -> list[dict]:
    reached = {e.get("stage") for e in events}
    out = []
    for s in STAGE_ORDER:
        evs = [e for e in events if e.get("stage") == s]
        out.append({"stage": s, "reached": s in reached, "evidence_count": len(evs)})
    return out


def threat_level(events: list[dict]) -> str:
    sev = {e.get("severity") for e in events}
    if "critical" in sev:
        return "Critical"
    if "high" in sev:
        return "High"
    if "medium" in sev:
        return "Medium"
    if events:
        return "Low"
    return "None"
