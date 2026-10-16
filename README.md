# AI Security Reviewer

A GitHub Action that reviews every pull request for security vulnerabilities. It posts inline comments that explain each issue and how to fix it.

It combines two engines:

1. **[Semgrep](https://semgrep.dev)** (rule-based static analysis) finds *candidates* on the lines the PR changed. It's fast and thorough, but it raises many false alarms.
2. **An LLM** reads each candidate with its surrounding code and decides whether it's actually exploitable: is the input attacker-controlled, is it already sanitized? It dismisses false positives and writes the explanation and fix for real issues. A second LLM pass reads the diff for things rules can't express, like a new admin route with no auth check or an IDOR.

```
PR opened ─► git diff (changed lines) ─► Semgrep ─► LLM triage ──┐
                                   └──────────► LLM diff scan ───┴─► dedupe/rank ─► PR review comments
```

## Results

<!-- Fill in after running the benchmark: python -m bench.run_benchmark ... -->
Measured on a stratified sample of the [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) (labeled vulnerable/safe test cases):

| Config | Caught | False alarms | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Semgrep only | _TBD_ | | | | |
| LLM only | | | | | |
| **Semgrep + LLM triage** | | | | | |

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
      - uses: <your-username>/AIPRChecker@v1
        with:
          llm-api-key: ${{ secrets.LLM_API_KEY }}
```

| Input | Default | |
|---|---|---|
| `llm-api-key` | required | Store as a repo secret |
| `llm-provider` | `openai` | `openai` = any OpenAI-compatible API (UF NaviGator, OpenAI, Ollama). `anthropic` = Claude API |
| `llm-base-url` | NaviGator | Base URL for OpenAI-compatible APIs |
| `llm-model` | `gpt-4o` | Use `claude-opus-5-5` with `llm-provider: anthropic` |
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

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava ../BenchmarkJava
python -m bench.run_benchmark --benchmark-dir ../BenchmarkJava --sample 200
```

The benchmark writes a Markdown and JSON report to `bench/results/`. LLM responses are cached, so re-runs are free. See [bench/datasets.md](bench/datasets.md) for how scoring works.

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
