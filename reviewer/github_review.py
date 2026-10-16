"""Post findings to a pull request as a single review with inline comments."""
from __future__ import annotations

import logging

import requests

from .diff import ChangedFile
from .models import Finding
from .pipeline import ReviewResult

log = logging.getLogger(__name__)

MARKER = "<!-- ai-security-reviewer -->"
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def comment_body(f: Finding) -> str:
    sev = f.severity.value
    cwe = f" · [{f.cwe}](https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html)" if f.cwe and f.cwe.startswith("CWE-") else ""
    parts = [
        f"{SEVERITY_ICON[sev]} **{f.title}** ({sev}{cwe})",
        "",
        f.explanation,
    ]
    if f.fix:
        parts += ["", "**Suggested fix:**", "", f.fix]
    detail = f"source: {f.source}, confidence: {f.confidence:.0%}"
    if f.rule_id:
        detail += f", rule: `{f.rule_id}`"
    parts += ["", f"<sub>{detail}</sub>", MARKER]
    return "\n".join(parts)


def summary_body(result: ReviewResult, unplaced: list[Finding]) -> str:
    n = len(result.findings)
    head = "### 🛡️ AI Security Review\n\n"
    if n == 0:
        head += "No security issues found in the changed code."
    else:
        counts: dict[str, int] = {}
        for f in result.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        breakdown = ", ".join(f"{SEVERITY_ICON[s]} {counts[s]} {s}" for s in SEVERITY_ICON if s in counts)
        head += f"Found **{n}** potential issue(s): {breakdown}."
    head += (
        f"\n\n<sub>Semgrep flagged {result.candidates} line(s) in this diff; the LLM dismissed "
        f"{result.dismissed} as false positives. {result.llm_only} issue(s) came from the LLM diff scan only."
    )
    if result.triage_errors:
        head += f" {result.triage_errors} candidate(s) could not be triaged."
    if result.truncated:
        head += f" {result.truncated} lower-priority issue(s) not shown."
    head += "</sub>"
    if unplaced:
        head += "\n\n**Issues outside the diff:**\n"
        for f in unplaced:
            head += f"\n- `{f.path}:{f.line}`: {f.title} ({f.severity.value}). {f.explanation}"
    return head + "\n" + MARKER


class GitHubReviewer:
    def __init__(self, token: str, repo: str, pr_number: int, api_url: str = "https://api.github.com"):
        self.base = f"{api_url}/repos/{repo}/pulls/{pr_number}"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def _existing_comment_keys(self) -> set[tuple[str, int, str]]:
        """(path, line, title) of comments this bot already posted, so re-runs don't spam."""
        keys = set()
        url = f"{self.base}/comments?per_page=100"
        while url:
            r = self.session.get(url, timeout=30)
            r.raise_for_status()
            for c in r.json():
                body = c.get("body", "")
                if MARKER in body and c.get("line"):
                    title = body.split("**")[1] if body.count("**") >= 2 else ""
                    keys.add((c["path"], c["line"], title))
            url = r.links.get("next", {}).get("url")
        return keys

    def _has_previous_review(self) -> bool:
        r = self.session.get(f"{self.base}/reviews?per_page=100", timeout=30)
        r.raise_for_status()
        return any(MARKER in (rv.get("body") or "") for rv in r.json())

    def post(self, result: ReviewResult, changed: dict[str, ChangedFile], commit_sha: str | None = None) -> None:
        existing = self._existing_comment_keys()
        comments, unplaced = [], []
        for f in result.findings:
            cf = changed.get(f.path)
            if not cf or f.line not in cf.added_lines:
                unplaced.append(f)
                continue
            if (f.path, f.line, f.title) in existing:
                continue
            comments.append({"path": f.path, "line": f.line, "side": "RIGHT", "body": comment_body(f)})

        if not comments and not unplaced and self._has_previous_review():
            log.info("nothing new since the last review; not posting")
            return

        payload = {"event": "COMMENT", "body": summary_body(result, unplaced), "comments": comments}
        if commit_sha:
            payload["commit_id"] = commit_sha
        r = self.session.post(f"{self.base}/reviews", json=payload, timeout=60)
        if r.status_code == 422 and comments:
            # A line GitHub couldn't place in the diff: retry with everything in the summary
            log.warning("GitHub rejected inline comments (%s); posting summary only", r.text[:300])
            payload["comments"] = []
            payload["body"] = summary_body(result, result.findings)
            r = self.session.post(f"{self.base}/reviews", json=payload, timeout=60)
        r.raise_for_status()
        log.info("posted review with %d inline comment(s)", len(payload["comments"]))
