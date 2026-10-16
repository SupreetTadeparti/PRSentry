"""Entrypoint.

Local:   python -m reviewer.main --path ../some-repo --base main
Action:  python -m reviewer.main --path "$GITHUB_WORKSPACE" --post   (PR info read from GITHUB_EVENT_PATH)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from .config import Config
from .diff import get_changed_files
from .llm_client import make_client
from .models import SEVERITY_RANK, Severity
from .pipeline import review


def _pr_event() -> dict:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("pull_request", {})


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AI security reviewer for pull requests")
    p.add_argument("--path", default=".", help="repository root")
    p.add_argument("--base", help="base ref/sha (default: PR base from the GitHub event)")
    p.add_argument("--head", help="head ref/sha (default: PR head from the event, else HEAD)")
    p.add_argument("--post", action="store_true", help="post a review to the PR")
    p.add_argument("--json-out", help="write findings JSON here")
    p.add_argument("--fail-on", choices=[s.value for s in Severity], help="exit 1 if any finding is at or above this severity")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("reviewer")

    cfg = Config()
    pr = _pr_event()
    base = args.base or pr.get("base", {}).get("sha")
    head = args.head or pr.get("head", {}).get("sha") or "HEAD"
    if not base:
        p.error("--base is required outside a pull_request event")

    root = os.path.abspath(args.path)
    changed = get_changed_files(root, base, head)
    log.info("%d changed file(s), %d hunk(s)", len(changed), sum(len(f.hunks) for f in changed.values()))

    result = review(cfg, make_client(cfg), root, changed)

    for f in result.findings:
        print(f"[{f.severity.value.upper():8}] {f.path}:{f.line}  {f.title}  ({f.cwe or '-'}, {f.confidence:.0%}, {f.source})")
    print(
        f"\n{len(result.findings)} finding(s). Semgrep candidates: {result.candidates}, "
        f"dismissed by LLM: {result.dismissed}, LLM-only: {result.llm_only}"
    )

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump([f.model_dump(mode="json") for f in result.findings], fh, indent=2)

    if args.post:
        from .github_review import GitHubReviewer

        if not (cfg.github_token and cfg.github_repository and pr.get("number")):
            log.error("--post needs GITHUB_TOKEN, GITHUB_REPOSITORY and a pull_request event")
            return 2
        GitHubReviewer(cfg.github_token, cfg.github_repository, pr["number"], cfg.github_api_url).post(
            result, changed, commit_sha=pr.get("head", {}).get("sha")
        )

    if args.fail_on:
        threshold = SEVERITY_RANK[Severity(args.fail_on)]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
