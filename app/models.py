from typing import Any, Literal
from pydantic import BaseModel, Field


class WazuhAlertInput(BaseModel):
    id: str | None = None
    timestamp: str | None = None
    rule: dict[str, Any] = Field(default_factory=dict)
    agent: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    full_log: str | None = None
    decoder: dict[str, Any] = Field(default_factory=dict)


class Tier2HandoffBrief(BaseModel):
    verdict: Literal[
        "Likely False Positive",
        "Suspicious - Needs Investigation",
        "Likely True Positive",
    ]
    confidence: Literal["Low", "Medium", "High"]
    recommended_severity: Literal["Low", "Medium", "High", "Critical"]
    false_positive_reason: str | None = None
    executive_summary: str
    key_iocs: list[str] = Field(default_factory=list)
    tier2_next_steps: list[str] = Field(default_factory=list)
    data_protection_notes: str = "Sensitive tokens redacted before analysis."
