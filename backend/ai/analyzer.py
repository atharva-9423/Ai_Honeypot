"""Hybrid AI analysis layer. Deterministic by default; LLM optional, never authoritative."""
from __future__ import annotations
import os
import time

BEHAVIOR_LABELS = {
    "honeytoken_accessed": "credential_discovery",
    "credential_discovery": "credential_discovery",
    "privilege_escalation_attempt": "privilege_escalation",
    "persistence_attempt": "persistence_attempt",
    "data_discovery": "data_discovery",
    "reconnaissance": "reconnaissance",
    "discovery": "discovery",
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def deterministic_analysis(commands: list[str], events: list[dict]) -> dict:
    if not events:
        return {
            "behavior": "no_suspicious_behavior",
            "confidence": 0.15,
            "intent_hypothesis": "insufficient_evidence",
            "severity": "low",
            "evidence": commands[-3:] if commands else [],
            "mitre_techniques": [],
            "recommended_action": "Continue observation; insufficient evidence of malicious staging.",
            "source": "deterministic",
            "note": "Insufficient evidence — no behavioral rule fired.",
        }
    # dominant = highest severity, then most frequent
    ranked = sorted(events, key=lambda e: SEVERITY_RANK.get(e.get("severity", "low"), 0), reverse=True)
    top = ranked[0]
    behavior = BEHAVIOR_LABELS.get(top.get("event_type"), "discovery")
    max_sev = max((SEVERITY_RANK.get(e.get("severity", "low"), 0) for e in events), default=0)
    sev_label = next(k for k, v in SEVERITY_RANK.items() if v == max_sev)
    conf = min(0.92, 0.55 + 0.08 * len(events) + (0.1 if any(e.get("event_type") == "honeytoken_accessed" for e in events) else 0))
    mitre = []
    for e in ranked[:3]:
        for m in (e.get("mitre") or []):
            if m not in mitre:
                mitre.append(m)
    hypotheses = {
        "credential_discovery": "credential_access",
        "privilege_escalation": "privilege_escalation",
        "persistence_attempt": "persistence",
        "data_discovery": "data_collection",
        "reconnaissance": "reconnaissance",
        "discovery": "system_discovery",
    }
    return {
        "behavior": behavior,
        "confidence": round(conf, 2),
        "intent_hypothesis": hypotheses.get(behavior, "unknown"),
        "severity": sev_label,
        "evidence": [e.get("evidence", [None])[0] or e.get("detail", "") for e in ranked[:5]],
        "mitre_techniques": mitre,
        "recommended_action": ("Isolate nothing externally; continue observation inside the virtual "
                               "environment and preserve session telemetry for analyst review."),
        "source": "deterministic",
    }


def analyze_session(commands: list[str], events: list[dict]) -> dict:
    """Entry point. Uses LLM only if SENTINEL_LLM_ENDPOINT is configured; else deterministic."""
    endpoint = os.environ.get("SENTINEL_LLM_ENDPOINT", "").strip()
    if not endpoint:
        result = deterministic_analysis(commands, events)
        result["ai_available"] = False
        result["ai_note"] = "AI analysis temporarily unavailable. Deterministic security analysis remains active."
        return result
    # Optional LLM path — strict: attacker data treated as untrusted, output validated, never executed.
    try:
        import json
        import urllib.request
        from ..security.guardrails import truncate_for_prompt, validate_ai_output
        from . import prompts
        payload = {"session_evidence": truncate_for_prompt("\n".join(commands[-20:])),
                   "events": truncate_for_prompt(json.dumps(events[-20:]))}
        req = urllib.request.Request(
            endpoint,
            data=json.dumps({"system": prompts.SYSTEM_INSTRUCTION,
                             "evidence": payload}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        ok, msg = validate_ai_output(data)
        if not ok:
            raise Valuepress_error(msg) if False else ValueError(msg)
        data["source"] = "llm"
        data["ai_available"] = True
        return data
    except Exception as e:
        result = deterministic_analysis(commands, events)
        result["ai_available"] = False
        result["ai_note"] = f"AI backend error ({e}); deterministic analysis remains active."
        return result
