"""Pass 2: have the LLM read each diff hunk for issues rule-based scanners miss."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from pydantic import ValidationError

from .context import numbered_context
from .diff import Hunk
from .llm_client import LLMClient, LLMError
from .models import Finding, Verdict
from .prompts import SCAN_SCHEMA, SCAN_SYSTEM, SCAN_USER

log = logging.getLogger(__name__)


def scan_hunk(llm: LLMClient, hunk: Hunk, root: str, radius: int = 20) -> list[Finding] | None:
    """Findings for one hunk, or None if the LLM call failed (distinct from "found nothing")."""
    user = SCAN_USER.format(
        path=hunk.path,
        hunk=hunk.text(),
        context=numbered_context(root, hunk.path, hunk.start, hunk.end, radius, mark=False),
    )
    try:
        data = llm.complete_json(SCAN_SYSTEM, user, SCAN_SCHEMA)
    except LLMError as e:
        log.warning("llm scan failed for %s:%d: %s", hunk.path, hunk.start, e)
        return None

    added = {no for no, _ in hunk.lines}
    findings = []
    for issue in data.get("issues", []):
        try:
            v = Verdict.model_validate(issue)
            line = int(issue["line"])
        except (ValidationError, KeyError, TypeError, ValueError):
            continue
        if not v.is_vulnerable or line not in added:
            continue  # ignore issues pinned to lines this PR didn't add
        findings.append(
            Finding(
                path=hunk.path,
                line=line,
                end_line=line,
                title=v.title or "Security issue",
                severity=v.severity,
                confidence=v.confidence,
                cwe=v.cwe or None,
                explanation=v.explanation,
                fix=v.fix,
                source="llm",
            )
        )
    return findings


def llm_scan(llm: LLMClient, hunks: list[Hunk], root: str, radius: int = 20, workers: int = 4) -> tuple[list[Finding], int]:
    """Returns (findings, number of hunks whose scan failed)."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda h: scan_hunk(llm, h, root, radius), hunks))
    return [f for batch in results if batch for f in batch], sum(r is None for r in results)
