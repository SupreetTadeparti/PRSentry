from reviewer.config import Config
from reviewer.diff import parse_diff
from reviewer.github_review import MARKER, comment_body, summary_body
from reviewer.llm_client import LLMError, _extract_json
from reviewer.models import Candidate, Finding, Severity
from reviewer.pipeline import dedupe, review
from reviewer.prompts import SCAN_SCHEMA

APP = """\
import sqlite3
API_KEY = "sk-live-123"

def get_user(name):
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(q)

@app.route("/admin/delete/<uid>")
def delete_user(uid):
    User.delete(uid)
"""

DIFF = """\
--- a/app.py
+++ b/app.py
@@ -0,0 +1,10 @@
""" + "".join(f"+{line}\n" for line in APP.splitlines())


class FakeLLM:
    """Confirms SQL injection, dismisses the secret as a false positive, and has the
    diff scan report missing auth on line 9 plus a hallucinated issue on an untouched line."""

    def __init__(self, fail_on: str | None = None):
        self.calls = []
        self.fail_on = fail_on

    def complete_json(self, system, user, schema):
        self.calls.append(user)
        if self.fail_on and self.fail_on in user:
            raise LLMError("boom")
        if schema is SCAN_SCHEMA:
            return {
                "issues": [
                    {"line": 9, "is_vulnerable": True, "confidence": 0.85, "severity": "high", "cwe": "CWE-862",
                     "title": "Missing authorization on admin route", "explanation": "Anyone can delete users.",
                     "fix": "Add @login_required and an admin check."},
                    {"line": 99, "is_vulnerable": True, "confidence": 0.9, "severity": "high", "cwe": "CWE-79",
                     "title": "Hallucinated", "explanation": "x", "fix": ""},
                    {"line": 5, "is_vulnerable": True, "confidence": 0.8, "severity": "critical", "cwe": "CWE-89",
                     "title": "SQL injection", "explanation": "dup of semgrep", "fix": ""},
                ]
            }
        if "CWE-89" in user:
            return {"is_vulnerable": True, "confidence": 0.95, "severity": "critical", "cwe": "CWE-89",
                    "title": "SQL injection in get_user", "explanation": "name is concatenated into SQL.",
                    "fix": "Use db.execute('... WHERE name = ?', (name,))"}
        return {"is_vulnerable": False, "confidence": 0.9, "severity": "low", "cwe": "",
                "title": "", "explanation": "Test key, not a real secret.", "fix": ""}


CANDIDATES = [
    Candidate(path="app.py", start_line=5, end_line=6, rule_id="sqli", message="sql", cwe="CWE-89"),
    Candidate(path="app.py", start_line=2, end_line=2, rule_id="secret", message="secret", cwe="CWE-798"),
]


def _review(tmp_path, llm, **cfg_overrides):
    (tmp_path / "app.py").write_text(APP)
    cfg = Config()
    for k, v in cfg_overrides.items():
        setattr(cfg, k, v)
    return review(cfg, llm, str(tmp_path), parse_diff(DIFF), candidates=list(CANDIDATES))


def test_review_triages_scans_and_dedupes(tmp_path):
    result = _review(tmp_path, FakeLLM())
    assert result.candidates == 2
    assert result.dismissed == 1  # the secret
    titles = [(f.line, f.title, f.source) for f in result.findings]
    assert titles == [
        (5, "SQL injection in get_user", "semgrep+llm"),  # LLM duplicate on line 5 collapsed into this
        (9, "Missing authorization on admin route", "llm"),
    ]
    assert result.llm_only == 1


def test_triage_prompt_includes_marked_context(tmp_path):
    llm = FakeLLM()
    _review(tmp_path, llm, enable_llm_scan=False)
    sqli_prompt = next(c for c in llm.calls if "CWE-89" in c)
    assert ">>    5:" in sqli_prompt and "get_user" in sqli_prompt


def test_llm_failure_is_counted_not_fatal(tmp_path):
    result = _review(tmp_path, FakeLLM(fail_on="CWE-89"), enable_llm_scan=False)
    assert result.triage_errors == 1
    assert result.findings == []


def test_min_confidence_and_cap(tmp_path):
    result = _review(tmp_path, FakeLLM(), min_confidence=0.9)
    assert [f.line for f in result.findings] == [5]
    result = _review(tmp_path, FakeLLM(), max_comments=1)
    assert len(result.findings) == 1 and result.truncated == 1


def test_dedupe_keeps_different_weaknesses_on_same_line():
    def f(cwe, src):
        return Finding(path="a.py", line=1, end_line=1, title=cwe, severity=Severity.high, confidence=0.9,
                       cwe=cwe, explanation="", fix="", source=src)

    kept = dedupe([f("CWE-89", "llm"), f("CWE-79", "llm"), f("CWE-89", "semgrep+llm")])
    assert sorted((k.cwe, k.source) for k in kept) == [("CWE-79", "llm"), ("CWE-89", "semgrep+llm")]


def test_comment_rendering(tmp_path):
    result = _review(tmp_path, FakeLLM())
    body = comment_body(result.findings[0])
    assert "**SQL injection in get_user**" in body and "cwe.mitre.org/data/definitions/89.html" in body
    assert "Suggested fix" in body and MARKER in body
    summary = summary_body(result, [])
    assert "Found **2**" in summary and "dismissed 1" in summary


def test_extract_json_tolerates_fences_and_prose():
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert _extract_json('Sure! Here it is: {"a": {"b": 2}} hope that helps') == {"a": {"b": 2}}
