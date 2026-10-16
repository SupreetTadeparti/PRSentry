"""Measure detection accuracy on the OWASP Benchmark, comparing three configurations:

  semgrep       Semgrep alone (a case is flagged if any result has the expected CWE)
  llm           LLM alone, reading the whole file as if it were a new PR
  semgrep+llm   Semgrep candidates with the expected CWE, kept only if the LLM confirms them

Usage:
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava ../BenchmarkJava
  python -m bench.run_benchmark --benchmark-dir ../BenchmarkJava --sample 200
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from reviewer.config import Config
from reviewer.diff import Hunk
from reviewer.llm_client import make_client
from reviewer.llm_scan import scan_hunk
from reviewer.models import Candidate
from reviewer.scanner import parse_semgrep_json, run_semgrep
from reviewer.triage import triage_one

from .owasp import TestCase, load_cases, materialize, sample_cases
from .score import Counts, cwe_matches, score

log = logging.getLogger("bench")
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIGS = ["semgrep", "llm", "semgrep+llm"]


class Cache:
    """JSON cache of LLM results so interrupted or repeated runs don't re-pay for calls."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)

    def get(self, key: str):
        return self.data.get(key)

    def put(self, key: str, value) -> None:
        with self.lock:
            self.data[key] = value
            if len(self.data) % 10 == 0:
                self._save()

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)

    def save(self) -> None:
        with self.lock:
            self._save()


def semgrep_candidates(args, cfg: Config, work_dir: str, cases: list[TestCase]) -> dict[str, list[Candidate]]:
    if args.semgrep_json:
        with open(args.semgrep_json, encoding="utf-8") as f:
            cands = parse_semgrep_json(json.load(f))
    else:
        configs = args.semgrep_config or cfg.semgrep_configs + ["p/java"]
        cands = run_semgrep([f"{c.name}.java" for c in cases], configs, cwd=work_dir)
    by_case: dict[str, list[Candidate]] = defaultdict(list)
    for c in cands:
        name = os.path.splitext(os.path.basename(c.path))[0]
        c.path = f"{name}.java"  # make relative to work_dir regardless of where semgrep ran
        by_case[name].append(c)
    return by_case


def whole_file_hunk(work_dir: str, name: str) -> Hunk:
    with open(os.path.join(work_dir, f"{name}.java"), encoding="utf-8") as f:
        lines = f.read().splitlines()
    return Hunk(f"{name}.java", 1, [(i + 1, txt) for i, txt in enumerate(lines)])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--benchmark-dir", required=True, help="path to a BenchmarkJava checkout")
    p.add_argument("--sample", type=int, default=200, help="number of test cases (0 = all ~2740)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--categories", help="comma-separated, e.g. sqli,xss,cmdi")
    p.add_argument("--configs", default=",".join(CONFIGS))
    p.add_argument("--semgrep-config", action="append", help="semgrep ruleset (repeatable)")
    p.add_argument("--semgrep-json", help="use precomputed `semgrep --json` output (e.g. run in Docker/WSL)")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--out", default=os.path.join(HERE, "results"))
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    cfg = Config()
    configs = [c.strip() for c in args.configs.split(",")]
    cases = sample_cases(load_cases(args.benchmark_dir), args.sample, args.seed, args.categories.split(",") if args.categories else None)
    n_vuln = sum(c.vulnerable for c in cases)
    log.info("%d test cases (%d vulnerable, %d safe)", len(cases), n_vuln, len(cases) - n_vuln)

    work_dir = os.path.join(HERE, ".work")
    materialize(cases, work_dir)

    predictions: dict[str, dict[str, bool]] = {}
    needs_semgrep = any(c in configs for c in ("semgrep", "semgrep+llm"))
    by_case = semgrep_candidates(args, cfg, work_dir, cases) if needs_semgrep else {}
    if "semgrep" in configs:
        predictions["semgrep"] = {c.name: any(cwe_matches(x.cwe, c.cwe) for x in by_case.get(c.name, [])) for c in cases}

    llm = make_client(cfg) if ("llm" in configs or "semgrep+llm" in configs) else None
    # make_client may swap in a default model, so name the cache after it's created
    cache = Cache(os.path.join(args.out, f"cache-{cfg.llm_provider}-{cfg.llm_model.replace('/', '_')}.json"))

    if "semgrep+llm" in configs:
        def triage_case(c: TestCase) -> bool:
            for cand in by_case.get(c.name, []):
                if not cwe_matches(cand.cwe, c.cwe):
                    continue
                key = f"triage:{c.name}:{cand.rule_id}:{cand.start_line}"
                v = cache.get(key)
                if v is None:
                    verdict = triage_one(llm, cand, work_dir, cfg.context_lines)
                    v = verdict.model_dump(mode="json") if verdict else {}
                    cache.put(key, v)
                if v.get("is_vulnerable") and v.get("confidence", 0) >= cfg.min_confidence:
                    return True
            return False

        log.info("running semgrep+llm triage ...")
        with ThreadPoolExecutor(args.workers) as pool:
            predictions["semgrep+llm"] = dict(zip([c.name for c in cases], pool.map(triage_case, cases)))
        cache.save()

    if "llm" in configs:
        def scan_case(c: TestCase) -> bool:
            key = f"scan:{c.name}"
            found = cache.get(key)
            if found is None:
                found = [f.model_dump(mode="json") for f in scan_hunk(llm, whole_file_hunk(work_dir, c.name), work_dir, 0)]
                cache.put(key, found)
            return any(cwe_matches(f.get("cwe"), c.cwe) and f.get("confidence", 0) >= cfg.min_confidence for f in found)

        log.info("running llm-only scan ...")
        with ThreadPoolExecutor(args.workers) as pool:
            predictions["llm"] = dict(zip([c.name for c in cases], pool.map(scan_case, cases)))
        cache.save()

    report = build_report(cases, predictions, cfg, args)
    os.makedirs(args.out, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    with open(os.path.join(args.out, f"benchmark-{stamp}.md"), "w", encoding="utf-8") as f:
        f.write(report["markdown"])
    with open(os.path.join(args.out, f"benchmark-{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump(report["json"], f, indent=2)
    print(report["markdown"])
    return 0


def build_report(cases: list[TestCase], predictions: dict[str, dict[str, bool]], cfg: Config, args) -> dict:
    n_vuln = sum(c.vulnerable for c in cases)
    results = {}
    lines = [
        "# OWASP Benchmark results",
        "",
        f"- Test cases: **{len(cases)}** ({n_vuln} truly vulnerable, {len(cases) - n_vuln} safe), seed {args.seed}",
        f"- LLM: `{cfg.llm_provider}` / `{cfg.llm_model}`, min confidence {cfg.min_confidence}",
        "",
        "| Config | Caught | False alarms | Precision | Recall | F1 | Score (TPR−FPR) |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in CONFIGS:
        if name not in predictions:
            continue
        overall, per_cat = score(cases, predictions[name])
        results[name] = {"overall": overall.as_dict(), "per_category": {k: v.as_dict() for k, v in per_cat.items()}}
        lines.append(
            f"| {name} | {overall.tp}/{overall.tp + overall.fn} | {overall.fp}/{overall.fp + overall.tn} | "
            f"{overall.precision:.0%} | {overall.tpr:.0%} | {overall.f1:.2f} | {overall.youden:+.2f} |"
        )

    if "semgrep" in results and "semgrep+llm" in results:
        fp_before = results["semgrep"]["overall"]["fp"]
        fp_after = results["semgrep+llm"]["overall"]["fp"]
        if fp_before:
            lines += ["", f"LLM triage removed **{(fp_before - fp_after) / fp_before:.0%}** of Semgrep's false alarms "
                          f"({fp_before} → {fp_after})."]

    lines += ["", "## Per category (recall / false-positive rate)", ""]
    names = [n for n in CONFIGS if n in results]
    lines += ["| Category | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    cats = sorted({c.category for c in cases})
    for cat in cats:
        cells = []
        for n in names:
            d = results[n]["per_category"].get(cat, Counts().as_dict())
            cells.append(f"{d['recall']:.0%} / {d['fpr']:.0%}")
        lines.append(f"| {cat} | " + " | ".join(cells) + " |")

    return {
        "markdown": "\n".join(lines) + "\n",
        "json": {
            "cases": len(cases), "vulnerable": n_vuln, "seed": args.seed,
            "llm": {"provider": cfg.llm_provider, "model": cfg.llm_model, "min_confidence": cfg.min_confidence},
            "results": results,
            "predictions": predictions,
        },
    }


if __name__ == "__main__":
    sys.exit(main())
