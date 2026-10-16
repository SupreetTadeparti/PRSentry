"""Data models shared across the reviewer pipeline."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


SEVERITY_RANK = {Severity.critical: 4, Severity.high: 3, Severity.medium: 2, Severity.low: 1}


class Candidate(BaseModel):
    """A raw finding from Semgrep, before LLM triage."""

    path: str
    start_line: int
    end_line: int
    rule_id: str
    message: str
    snippet: str = ""
    cwe: Optional[str] = None


class Verdict(BaseModel):
    """What the LLM returns for a single candidate or diff issue."""

    is_vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity = Severity.medium
    cwe: Optional[str] = None
    title: str = ""
    explanation: str = ""
    fix: str = ""


class Finding(BaseModel):
    """A confirmed issue that will be reported on the PR."""

    path: str
    line: int
    end_line: int
    title: str
    severity: Severity
    confidence: float
    cwe: Optional[str] = None
    explanation: str
    fix: str
    source: str  # "semgrep+llm" | "llm" | "semgrep"
    rule_id: Optional[str] = None

    def key(self) -> tuple:
        return (self.path, self.line, (self.cwe or self.title).lower())
