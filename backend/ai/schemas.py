"""Pydantic schemas for AI output contract."""
from pydantic import BaseModel, Field


class MitreTechnique(BaseModel):
    id: str
    name: str


class AIAnalysis(BaseModel):
    behavior: str
    confidence: float = Field(ge=0.0, le=1.0)
    intent_hypothesis: str
    severity: str
    evidence: list[str]
    mitre_techniques: list[MitreTechnique]
    recommended_action: str
