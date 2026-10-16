"""Prompts and JSON schemas for the two LLM passes."""
from __future__ import annotations

_VERDICT_PROPERTIES = {
    "is_vulnerable": {"type": "boolean"},
    "confidence": {"type": "number", "description": "0.0-1.0: how sure you are this is exploitable"},
    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
    "cwe": {"type": "string", "description": "e.g. CWE-89, or empty string if unsure"},
    "title": {"type": "string", "description": "Short name of the issue, e.g. 'SQL injection in login query'"},
    "explanation": {"type": "string", "description": "Why this is (or is not) exploitable, 2-4 sentences"},
    "fix": {"type": "string", "description": "Concrete fix, ideally a corrected code snippet"},
}

VERDICT_SCHEMA = {
    "type": "object",
    "properties": _VERDICT_PROPERTIES,
    "required": list(_VERDICT_PROPERTIES),
    "additionalProperties": False,
}

_ISSUE_PROPERTIES = {"line": {"type": "integer", "description": "Line number from the hunk"}, **_VERDICT_PROPERTIES}

SCAN_SCHEMA = {
    "type": "object",
    "properties": {
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": _ISSUE_PROPERTIES,
                "required": list(_ISSUE_PROPERTIES),
                "additionalProperties": False,
            },
        }
    },
    "required": ["issues"],
    "additionalProperties": False,
}

TRIAGE_SYSTEM = """You are an application security engineer triaging static-analysis results on a pull request.
A rule-based scanner flagged the code below. Scanners produce many false positives, so judge it yourself:
- Trace where the data comes from. Is it attacker-controlled (request params, headers, body, files, env from users)?
- Is it already sanitized, parameterized, escaped, validated or constant?
- Is the code reachable in production, or is it a test, fixture, or example?
Mark is_vulnerable=true only if a realistic attacker could exploit it. If it is a false positive,
say why in `explanation` and leave `fix` empty. Be concise and specific to this code."""

TRIAGE_USER = """Scanner rule: {rule_id}
Scanner message: {message}
Reported CWE: {cwe}
File: {path} (flagged lines {start_line}-{end_line})

Code context (line numbers on the left, flagged lines marked with >>):
{context}"""

SCAN_SYSTEM = """You are an application security engineer reviewing a pull request diff.
Look ONLY at the added lines shown, using the surrounding context to understand them. Report real,
exploitable security issues that a pattern-based scanner would likely miss, such as:
- missing authentication or authorization checks on new routes/handlers
- insecure direct object references (IDOR): user-supplied IDs used without ownership checks
- broken access control, privilege escalation, mass assignment
- insecure crypto choices, weak randomness for security tokens, disabled TLS verification
- business-logic flaws, race conditions on security-relevant state
- hardcoded secrets, injection, SSRF, path traversal, unsafe deserialization
Do NOT report style issues, missing tests, or speculative problems with no clear attack path.
If there are no real issues, return {"issues": []}. Every reported line must be one of the added lines."""

SCAN_USER = """File: {path}

Added lines (line number: code):
{hunk}

Surrounding file context:
{context}"""
