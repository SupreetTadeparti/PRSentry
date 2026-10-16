# PRSentry

**Catches security bugs in your pull requests before they merge, and filters out the false alarms that make static analyzers easy to ignore.**

PRSentry is a GitHub Action that reviews every pull request for security vulnerabilities. It posts inline comments that explain each issue and how to fix it.

It combines two engines:

1. **[Semgrep](https://semgrep.dev)** (rule-based static analysis) finds *candidates* on the lines the PR changed. It's fast and thorough, but it raises many false alarms.
2. **An LLM** reads each candidate with its surrounding code and decides whether it's actually exploitable: is the input attacker-controlled, is it already sanitized? It dismisses false positives and writes the explanation and fix for real issues. A second LLM pass reads the diff for things rules can't express, like a new admin route with no auth check or an IDOR.

```
PR opened ─► git diff (changed lines) ─► Semgrep ─► LLM triage ──┐
                                   └──────────► LLM diff scan ───┴─► dedupe/rank ─► PR review comments
```

## Results

### OWASP Benchmark

Measured on 200 test cases from the [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava): 100 truly vulnerable and 100 safe look-alikes across 11 categories. The sample is a held-out stratified sample (seed 7). The model is `gpt-oss-120b` via UF NaviGator, run in October 2026.

| Config | Caught | False alarms | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Semgrep only | 90/100 | 42/100 | 68% | 90% | 0.78 |
| LLM only | 82/100 | 29/100 | 74% | 82% | 0.78 |
| **Semgrep + LLM triage** | **83/100** | **26/100** | **76%** | **83%** | **0.79** |

- **LLM triage removed 38% of Semgrep's false alarms** (42 → 26) and raised precision from 68% to 76%. The cost was 7 missed true positives, mostly in command injection and trust-boundary cases.
- The biggest gains were XSS (56% → 0% false-alarm rate with recall unchanged) and SQL injection (67% → 22%, at the cost of one missed case).
- LLM triage didn't reduce false alarms for LDAP or XPath injection.

Full report, per-category table and every cached LLM verdict: [bench/results/heldout-seed7/](bench/results/heldout-seed7/). Methodology (blinding, held-out seed): [bench/datasets.md](bench/datasets.md).

### Demo PR

On [demo/vulnerable_app.py](demo/vulnerable_app.py), which has 7 planted bugs and 1 safe decoy, PRSentry caught **6 of 7** and didn't flag the decoy. Two of the catches, a missing admin auth check and an IDOR, came from the LLM diff scan alone. Semgrep's rules can't express them. The one miss was a path traversal through `send_file`.

## Use it in a repo

```yaml
# .github/workflows/security-review.yml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: SupreetTadeparti/PRSentry@v1
        with:
          llm-api-key: ${{ secrets.LLM_API_KEY }}
```

| Input | Default | |
|---|---|---|
| `llm-api-key` | required | Store as a repo secret |
| `llm-provider` | `openai` | `openai` = any OpenAI-compatible API (UF NaviGator, OpenAI, Ollama). `anthropic` = Claude API |
| `llm-base-url` | NaviGator | Base URL for OpenAI-compatible APIs |
| `llm-model` | `gpt-oss-120b` | Any model your endpoint serves. Use `claude-opus-5-5` with `llm-provider: anthropic` |
| `min-confidence` | `0.6` | Drop findings the LLM is less sure about |
| `max-comments` | `15` | Cap on inline comments per run |
| `enable-llm-scan` | `true` | LLM pass for logic/auth issues Semgrep can't see |
| `fail-on` | (empty) | e.g. `high`: fail the check on high/critical findings |

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

export LLM_API_KEY=...            # NaviGator / OpenAI key
python -m reviewer.main --path /path/to/repo --base main
```

> Semgrep doesn't fully support native Windows. Use WSL or Docker for it, or run the benchmark with `--semgrep-json` on precomputed output.

## Benchmark

The easiest way to run it is in GitHub Actions: **Actions → Benchmark → Run workflow** (or `gh workflow run benchmark.yml -f sample=200 -f seed=7`). The results table appears on the run's summary page, and the full report and the cached LLM responses are uploaded as an artifact.

To run it locally on Linux, macOS or WSL:

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava ../BenchmarkJava
python -m bench.run_benchmark --benchmark-dir ../BenchmarkJava --sample 200 --seed 7
```

The test files are *blinded* before either tool sees them. The category in the URL, the OWASP license header, and the package and class names are all removed, so the LLM can't tell it's looking at a benchmark. See [bench/datasets.md](bench/datasets.md) for how scoring works.

## Tests

```bash
pytest -q
```

The tests use a fake LLM and fake Semgrep output, so they run offline at no cost.

## Layout

| Path | |
|---|---|
| `reviewer/diff.py` | Parses `git diff` into changed files and added-line numbers |
| `reviewer/scanner.py` | Runs Semgrep and keeps findings on changed lines |
| `reviewer/triage.py` | LLM confirms or dismisses each Semgrep candidate |
| `reviewer/llm_scan.py` | LLM scans diff hunks for auth/logic issues |
| `reviewer/pipeline.py` | Orchestration, confidence filter, dedupe, ranking |
| `reviewer/github_review.py` | Posts one PR review with inline comments; skips repeats on re-runs |
| `reviewer/llm_client.py` | OpenAI-compatible and Claude backends, JSON output |
| `bench/` | OWASP Benchmark harness and scoring |
| `demo/vulnerable_app.py` | Planted-bug Flask app with an answer key, for demo PRs |
