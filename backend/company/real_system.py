"""The 'real' demo company — production truth for the Real System tab.

Fictional company, fictional values, demo scope only. These values are the
REFERENCE the honeypot decoys are compared against: no AI-generated decoy
may ever equal one of these (enforced by the decoy validator).
"""
from __future__ import annotations

COMPANY = {
    "name": "Meridian Logistics",
    "domain": "meridian.example",
    "prod_host": "prod-meridian-01",
    "db_host": "db.internal.meridian.example",
    "note": "Fictional demo company. Reference data for evaluation only.",
}

REAL_CREDENTIALS = [
    {"system": "Production database", "location": "db.internal.meridian.example",
     "username": "meridian_prod", "password": "M3r1dian#Prod-7741",
     "sensitivity": "critical"},
    {"system": "API service token", "location": "api.meridian.example",
     "username": "svc_api", "password": "meridian_live_7f3a9c2e51",
     "sensitivity": "high"},
    {"system": "AWS production", "location": "us-east-1",
     "username": "AKIA2F5N7EXAMPLE9QRS",
     "password": "9f2kD3mQEXAMPLE8x1vBn4s6hJ0aZcXeWw",
     "sensitivity": "critical"},
]

# Every real secret value — the decoy validator rejects any generated file
# containing one of these verbatim.
REAL_SECRETS = [c["password"] for c in REAL_CREDENTIALS] + \
               [c["username"] for c in REAL_CREDENTIALS
                if c["username"].startswith("AKIA")]

# Distinctive real-document tokens (client names, emails). Decoys must not
# reuse these either, so the terminal never shows Real-tab content.
REAL_DISTINCTIVE = [
    "Acme Industrial", "ops@client-a.example",
    "Bluefin Retail", "it@client-b.example",
    "Harbor Freightways", "dispatch@client-c.example",
    "241800", "256400", "249900",
]

REAL_DOCUMENTS = [
    {"path": "/srv/meridian/customers_real.csv", "label": "Customer master export",
     "preview": ("id,name,email,plan\n"
                 "201,Acme Industrial,ops@client-a.example,enterprise\n"
                 "202,Bluefin Retail,it@client-b.example,team\n"
                 "203,Harbor Freightways,dispatch@client-c.example,enterprise")},
    {"path": "/srv/meridian/finance_q3_real.csv", "label": "Q3 revenue (audited)",
     "preview": ("month,revenue_usd\n2024-07,241800\n2024-08,256400\n2024-09,249900")},
    {"path": "/srv/meridian/docs/backup_policy.txt", "label": "Backup policy",
     "preview": ("Nightly encrypted backups to vault storage.\n"
                 "Cloud credentials live in the secrets vault ONLY —\n"
                 "never in /backup or environment files.")},
]

REAL_LOGS = [
    {"path": "/var/log/auth.log", "label": "Production auth log (sample)",
     "preview": ("Jan 12 08:02:11 prod-meridian-01 sshd[410]: Accepted key "
                 "for admin from 10.0.1.20")},
]

REAL_SERVICES = [
    {"name": "meridian-api", "port": 8080, "host": "prod-meridian-01"},
    {"name": "postgres", "port": 5432, "host": "db.internal.meridian.example"},
    {"name": "nightly-backup", "port": None, "host": "cron 02:00 UTC"},
]


def real_system_model() -> dict:
    """Static production-truth payload for the Real System tab."""
    return {"company": COMPANY, "credentials": REAL_CREDENTIALS,
            "documents": REAL_DOCUMENTS, "logs": REAL_LOGS,
            "services": REAL_SERVICES}
