"""Glue: changed files -> Semgrep -> LLM triage + LLM scan -> deduped findings."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import Config
from .diff import ChangedFile
from .llm_client import LLMClient
from .llm_scan import llm_scan
from .models import SEVERITY_RANK, Candidate, Finding
from .scanner import filter_to_changed, run_semgrep
from .triage import to_finding, triage

log = logging.getLogger(__name__)


@dataclass
class ReviewResult:
    findings: list[Finding] = field(default_factory=list)
    candidates: int = 0  # Semgrep hits on changed lines
    dismissed: int = 0  # candidates the LLM judged false positives
    triage_errors: int = 0
    llm_only: int = 0  # findings only the LLM diff scan produced
    truncated: int = 0  # findings dropped by the max_comments cap


def dedupe(findings: list[Finding], window: int = 2) -> list[Finding]:
    """Collapse findings on (nearly) the same line about the same weakness. Keep the best one."""
    ranked = sorted(
        findings,
        key=lambda f: (f.source != "semgrep+llm", -SEVERITY_RANK[f.severity], -f.confidence),
    )
    kept: list[Finding] = []
    for f in ranked:
        dup = any(
            k.path == f.path
            and abs(k.line - f.line) <= window
            and (k.cwe == f.cwe or k.title.lower() == f.title.lower() or not (k.cwe and f.cwe))
            for k in kept
        )
        if not dup:
            kept.append(f)
    return kept


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], -f.confidence, f.path, f.line))


def review(cfg: Config, llm: LLMClient, root: str, changed: dict[str, ChangedFile], candidates: list[Candidate] | None = None) -> ReviewResult:
    result = ReviewResult()
    if not changed:
        return result

    if candidates is None:
        candidates = filter_to_changed(run_semgrep(sorted(changed), cfg.semgrep_configs, cwd=root), changed)
    result.candidates = len(candidates)
    log.info("semgrep: %d candidate(s) on changed lines", len(candidates))

    findings: list[Finding] = []
    for c, v in triage(llm, candidates, root, cfg.context_lines):
        if v is None:
            result.triage_errors += 1
        elif v.is_vulnerable:
            findings.append(to_finding(c, v))
        else:
            result.dismissed += 1

    if cfg.enable_llm_scan:
        hunks = [h for f in changed.values() for h in f.hunks][: cfg.max_hunks]
        extra = llm_scan(llm, hunks, root, cfg.context_lines)
        log.info("llm scan: %d issue(s) from %d hunk(s)", len(extra), len(hunks))
        findings.extend(extra)

    findings = [f for f in findings if f.confidence >= cfg.min_confidence]
    findings = rank(dedupe(findings))
    result.llm_only = sum(f.source == "llm" for f in findings)
    result.truncated = max(0, len(findings) - cfg.max_comments)
    result.findings = findings[: cfg.max_comments]
    return result
