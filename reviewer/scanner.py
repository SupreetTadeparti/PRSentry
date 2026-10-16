"""Run Semgrep and turn its JSON output into Candidates."""
from __future__ import annotations

import json
import logging
import os
import subprocess

from .diff import ChangedFile
from .models import Candidate

log = logging.getLogger(__name__)


def _first_cwe(metadata: dict) -> str | None:
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if not cwe:
        return None
    # Semgrep formats these like "CWE-89: Improper Neutralization of ..."
    return str(cwe).split(":")[0].strip()


def parse_semgrep_json(data: dict, root: str = ".") -> list[Candidate]:
    candidates = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        path = os.path.relpath(r["path"], root) if os.path.isabs(r["path"]) else r["path"]
        candidates.append(
            Candidate(
                path=path.replace("\\", "/"),
                start_line=r["start"]["line"],
                end_line=r["end"]["line"],
                rule_id=r.get("check_id", "unknown"),
                message=extra.get("message", ""),
                snippet=extra.get("lines", ""),
                cwe=_first_cwe(extra.get("metadata", {})),
            )
        )
    for err in data.get("errors", []):
        log.debug("semgrep error: %s", err.get("message", err))
    return candidates


def run_semgrep(paths: list[str], configs: list[str], cwd: str = ".") -> list[Candidate]:
    """Run semgrep on the given paths (relative to cwd)."""
    if not paths:
        return []
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off"]
    for c in configs:
        cmd += ["--config", c.strip()]
    cmd += paths
    log.info("running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    # Exit code 1 means "findings present"; anything else above that is an error
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return parse_semgrep_json(json.loads(proc.stdout or "{}"), root=cwd)


def filter_to_changed(candidates: list[Candidate], changed: dict[str, ChangedFile]) -> list[Candidate]:
    """Keep only findings that overlap a line the PR added."""
    kept = []
    for c in candidates:
        f = changed.get(c.path)
        if f and any(c.start_line <= ln <= c.end_line for ln in f.added_lines):
            kept.append(c)
    return kept
