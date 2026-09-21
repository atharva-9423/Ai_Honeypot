"""Honeytoken registry."""
HONEYTOKENS = {
    "/backup/cloud_credentials.txt": {
        "id": "HT-CLOUD-001",
        "description": "Synthetic cloud credentials decoy",
        "severity": "high",
    },
    "/srv/meridian/api/.env": {
        "id": "HT-AWS-002",
        "description": "Synthetic AWS environment-file decoy (documented example keys)",
        "severity": "high",
    },
}


def is_honeytoken(path: str) -> bool:
    from .virtual_fs import VirtualFS
    return VirtualFS.normalize(path) in HONEYTOKENS
