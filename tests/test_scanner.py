from reviewer.diff import parse_diff
from reviewer.scanner import filter_to_changed, parse_semgrep_json

SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query",
            "path": "app.py",
            "start": {"line": 5},
            "end": {"line": 6},
            "extra": {
                "message": "Possible SQL injection",
                "lines": "q = ...",
                "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]},
            },
        },
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app.py",
            "start": {"line": 40},
            "end": {"line": 40},
            "extra": {"message": "eval", "metadata": {"cwe": "CWE-95: Eval Injection"}},
        },
    ],
    "errors": [],
}


def test_parse_semgrep_json_extracts_cwe_id():
    cands = parse_semgrep_json(SEMGREP_OUTPUT)
    assert [c.cwe for c in cands] == ["CWE-89", "CWE-95"]
    assert cands[0].start_line == 5 and cands[0].end_line == 6


def test_filter_keeps_only_findings_on_added_lines():
    changed = parse_diff("--- a/app.py\n+++ b/app.py\n@@ -4,1 +4,3 @@\n ctx\n+a\n+b\n")
    kept = filter_to_changed(parse_semgrep_json(SEMGREP_OUTPUT), changed)
    assert [c.cwe for c in kept] == ["CWE-89"]  # line 40 wasn't touched by the PR
