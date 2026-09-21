"""SENTINEL input validation + sandbox policy + output validation (safety layer)."""
from __future__ import annotations
import re

MAX_COMMAND_LEN = 1024
MAX_PROMPT_CHARS = 6000

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"system\s*prompt",
    r"reveal\s+.*prompt",
    r"execute\s+.*host",
    r"jailbreak",
    r"dan\s+mode",
]

_ALLOWED_ACTIONS = {
    "CREATE_DECOY_FILE",
    "CREATE_SYNTHETIC_CREDENTIAL",
    "CREATE_DECOY_DIRECTORY",
    "CHANGE_SYNTHETIC_SERVICE_RESPONSE",
    "INCREASE_LOGGING",
    "MARK_HONEYTOKEN",
}

_FORBIDDEN_ACTIONS = {
    "EXECUTE_HOST_COMMAND",
    "NETWORK_SCAN",
    "EXTERNAL_CONNECTION",
    "COUNTER_ATTACK",
    "REAL_CREDENTIAL_ACCESS",
    "REAL_FILE_ACCESS",
}


def sanitize_command(raw: str) -> tuple[str, list[str]]:
    """Return (cleaned, warnings). Never raises on attacker input."""
    warnings: list[str] = []
    cmd = (raw or "").strip().replace("\x00", "")
    # strip control chars except newline/tab
    cmd = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cmd)
    if len(cmd) > MAX_COMMAND_LEN:
        warnings.append("Command truncated to 1024 characters.")
        cmd = cmd[:MAX_COMMAND_LEN]
    low = cmd.lower()
    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, low):
            warnings.append("Prompt-injection pattern detected; treated as untrusted data only.")
            break
    return cmd, warnings


def policy_decision(action: str) -> str:
    if action in _FORBIDDEN_ACTIONS:
        return "BLOCKED"
    if action in _ALLOWED_ACTIONS:
        return "ALLOWED"
    return "BLOCKED"


def truncate_for_prompt(text: str, limit: int = MAX_PROMPT_CHARS) -> str:
    text = text or ""
    return text if len(text) <= limit else text[-limit:]


def validate_ai_output(data: dict) -> tuple[bool, str]:
    required = {"behavior", "confidence", "intent_hypothesis", "severity",
                "evidence", "mitre_techniques", "recommended_action"}
    if not isinstance(data, dict):
        return False, "AI output is not an object."
    if not required.issubset(set(data.keys())):
        return False, f"AI output missing keys: {required - set(data.keys())}"
    try:
        conf = float(data["confidence"])
        if not (0.0 <= conf <= 1.0):
            return False, "confidence out of range."
    except Exception:
        return False, "confidence must be a number 0..1."
    if data["severity"] not in {"low", "medium", "high", "critical"}:
        return False, "invalid severity."
    if not isinstance(data["evidence"], list):
        return False, "evidence must be a list."
    return True, "ok"
