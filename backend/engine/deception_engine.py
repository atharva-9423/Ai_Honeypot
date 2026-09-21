"""Adaptive deception engine — gated by policy engine. Synthetic resources only."""
from __future__ import annotations
import posixpath
import time
from ..security.guardrails import policy_decision

DECOY_CRED_PATH = "/opt/backup/credentials.txt"
DECOY_DB_PATH = "/var/backups/customer_db.csv"

DECOY_CRED_CONTENT = (
    "database_user: backup_service\n"
    "database_password: BkSvc#Nightly-55210\n"
    "host: db.internal.meridian.example\n"
)

DECOY_DB_CONTENT = (
    "# SYNTHETIC DECOY DATA — NOT REAL\n"
    "id,name,email\n"
    "1,synthetic-user-01,user01@example.internal\n"
    "2,synthetic-user-02,user02@example.internal\n"
)


def maybe_deploy(session, new_events: list[dict]) -> list[dict]:
    """Decide + apply allowed deception actions. Returns deception action records."""
    actions: list[dict] = []
    types = {e.get("event_type") for e in new_events}
    cred_seen = "credential_discovery" in types or "honeytoken_accessed" in types
    data_seen = "data_discovery" in types

    if cred_seen and not session.deception_deployed:
        if policy_decision("CREATE_DECOY_FILE") == "ALLOWED":
            try:
                session.fs.mkdir("/opt/backup")
            except Exception:
                pass
            if not session.fs.is_file(DECOY_CRED_PATH):
                session.fs.write_file(DECOY_CRED_PATH, DECOY_CRED_CONTENT)
            session.deception_deployed = True
            actions.append({"timestamp": time.time(), "action": "CREATE_DECOY_FILE",
                            "target": DECOY_CRED_PATH,
                            "reason": "Credential-discovery behavior observed; planted synthetic decoy credentials for continued observation."})
    if data_seen and not any(a.get("target") == DECOY_DB_PATH for a in session.deception_actions):
        if policy_decision("CREATE_DECOY_FILE") == "ALLOWED":
            try:
                session.fs.mkdir("/var/backups")
            except Exception:
                pass
            if not session.fs.is_file(DECOY_DB_PATH):
                session.fs.write_file(DECOY_DB_PATH, DECOY_DB_CONTENT)
            actions.append({"timestamp": time.time(), "action": "CREATE_DECOY_FILE",
                            "target": DECOY_DB_PATH,
                            "reason": "Data-discovery behavior observed; planted synthetic decoy dataset."})
    session.deception_actions.extend(actions)
    return actions


# ---- Learning loop: expand decoys where the visitor shows interest ----
# Path prefix -> interest area. Follow-up decoys are deterministic templates
# (instant, bounded); the initial environment replica is the AI piece.
AREA_RULES = (
    ("/srv/meridian/finance", "finance"),
    ("/srv/meridian/api", "api"),
    ("/srv/meridian/docs", "docs"),
    ("/srv/meridian/customers", "customers"),
    ("/srv/meridian/customer_export", "customers"),
    ("/backup", "backups"),
)

EXPANSION_TEMPLATES = {
    "finance": ("/srv/meridian/finance_q4_draft.csv",
                "month,revenue_usd,status\n"
                "2024-10,198400,draft\n"
                "2024-11,201750,draft\n",
                "Sustained finance interest; planted draft figures to deepen observation."),
    "api": ("/srv/meridian/api/legacy_keys.txt",
            "# Legacy service keys — ROTATED OUT 2024-11, retained for audit\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
            "Repeated API/credential interest; planted legacy key file."),
    "docs": ("/srv/meridian/docs/vpn_access.txt",
             "Meridian VPN access\n"
             "- gateway: vpn.meridian.example\n"
             "- auth: SSO only — no shared passwords issued\n",
             "Repeated docs interest; planted access note."),
    "customers": ("/srv/meridian/customer_export_2024.csv",
                  "id,name,email,plan\n"
                  "105,Carson Warehousing,ops@client-e.example,team\n"
                  "106,Delta Produce,admin@client-f.example,enterprise\n",
                  "Repeated customer-data interest; planted further export."),
    "backups": ("/srv/meridian/backups/snapshot_readme.txt",
                "Snapshot store\n"
                "- snapshots are encrypted and vaulted; nothing restorable from here\n",
                "Repeated backup interest; planted store note."),
}

MAX_EXPANSIONS = 3
EXPANSION_THRESHOLD = 2


def area_of(path: str) -> str | None:
    p = (path or "").lower()
    for prefix, area in AREA_RULES:
        if p == prefix:
            return area
        # match subpaths (finance/...) AND sibling files (finance_q3.csv)
        if p.startswith(prefix) and p[len(prefix):len(prefix) + 1] in ("/", "_", "."):
            return area
    return None


def maybe_expand(session) -> list[dict]:
    """Plant at most MAX_EXPANSIONS follow-up decoys in areas with
    sustained interest (>= EXPANSION_THRESHOLD accesses). Policy-gated."""
    if policy_decision("CREATE_DECOY_FILE") != "ALLOWED":
        return []
    actions: list[dict] = []
    done = {e.get("area") for e in session.expansions}
    ranked = sorted(session.interests.items(), key=lambda kv: kv[1], reverse=True)
    for area, count in ranked:
        if len(session.expansions) >= MAX_EXPANSIONS:
            break
        if count < EXPANSION_THRESHOLD or area in done:
            continue
        tpl = EXPANSION_TEMPLATES.get(area)
        if not tpl:
            continue
        target, content, reason = tpl
        try:
            session.fs.mkdir(posixpath.dirname(target))
        except Exception:
            pass
        if session.fs.is_file(target):
            continue
        session.fs.write_file(target, content)
        record = {"timestamp": time.time(), "action": "CREATE_DECOY_FILE",
                  "target": target, "area": area,
                  "reason": f"Interest-driven expansion ({count} accesses): {reason}"}
        session.expansions.append({"area": area, "target": target,
                                   "timestamp": record["timestamp"]})
        session.deception_actions.append(record)
        actions.append(record)
    return actions
