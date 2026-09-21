"""Strict Pydantic schemas for Groq command-interpretation responses."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, Field

CommandType = Literal[
    "file_read", "dir_list", "file_stat", "file_search", "line_count",
    "system_info", "echo_text", "unknown", "invalid",
]

Behavior = Literal[
    "credential_discovery", "credential_access",
    "system_log_discovery", "file_discovery",
    "system_discovery", "network_discovery",
    "unknown_command", "no_suspicious_behavior",
]

Severity = Literal["low", "medium", "high"]


class DeceptionRecommendation(BaseModel):
    action: str = Field(max_length=64)
    reason: str = Field(max_length=500)


class GroqCommandInterpretation(BaseModel):
    valid: bool
    command_type: CommandType
    normalized_command: str | None = Field(default=None, max_length=512)
    target: str | None = Field(default=None, max_length=512)
    arguments: list[str] = Field(default_factory=list, max_length=20)
    intent: str = Field(default="unknown", max_length=300)
    simulated_output: str | None = Field(default=None, max_length=2000)
    behavior: Behavior = "unknown_command"
    severity: Severity = "low"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    requires_virtual_state: bool = True
    deception_recommendation: DeceptionRecommendation | None = None

    class Config:
        extra = "ignore"


class AttackHelp(BaseModel):
    """One command per list entry: `command — purpose`."""
    help: list[str] = Field(max_length=40)
