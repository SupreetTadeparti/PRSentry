"""Pass 1: have the LLM confirm or reject each Semgrep candidate."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from pydantic import ValidationError

from .context import numbered_context
from .llm_client import LLMClient, LLMError
from .models import Candidate, Finding, Verdict
from .prompts import TRIAGE_SYSTEM, TRIAGE_USER, VERDICT_SCHEMA

log = logging.getLogger(__name__)


def triage_one(llm: LLMClient, c: Candidate, root: str, radius: int = 20) -> Verdict | None:
    user = TRIAGE_USER.format(
        rule_id=c.rule_id,
        message=c.message,
        cwe=c.cwe or "unknown",
        path=c.path,
        start_line=c.start_line,
        end_line=c.end_line,
        context=numbered_context(root, c.path, c.start_line, c.end_line, radius),
    )
    try:
        return Verdict.model_validate(llm.complete_json(TRIAGE_SYSTEM, user, VERDICT_SCHEMA))
    except (LLMError, ValidationError) as e:
        log.warning("triage failed for %s:%d (%s): %s", c.path, c.start_line, c.rule_id, e)
        return None


def to_finding(c: Candidate, v: Verdict) -> Finding:
    return Finding(
        path=c.path,
        line=c.start_line,
        end_line=c.end_line,
        title=v.title or c.rule_id.split(".")[-1],
        severity=v.severity,
        confidence=v.confidence,
        cwe=v.cwe or c.cwe,
        explanation=v.explanation or c.message,
        fix=v.fix,
        source="semgrep+llm",
        rule_id=c.rule_id,
    )


def triage(llm: LLMClient, candidates: list[Candidate], root: str, radius: int = 20, workers: int = 4) -> list[tuple[Candidate, Verdict | None]]:
    """Return every candidate paired with its verdict (None if the LLM call failed)."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        verdicts = list(pool.map(lambda c: triage_one(llm, c, root, radius), candidates))
    return list(zip(candidates, verdicts))
