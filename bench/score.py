"""Scoring: confusion matrix per category and overall, OWASP-Benchmark style."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

# Tools rarely agree on the exact CWE, so treat closely related ones as equivalent.
CWE_GROUPS = [
    {"CWE-327", "CWE-326", "CWE-328", "CWE-916", "CWE-759", "CWE-760"},  # weak crypto / hashing
    {"CWE-330", "CWE-338", "CWE-331"},  # weak randomness
    {"CWE-614", "CWE-1004", "CWE-315", "CWE-539"},  # insecure cookie
    {"CWE-78", "CWE-77"},  # command injection
    {"CWE-89", "CWE-564"},  # SQL injection
    {"CWE-79", "CWE-80", "CWE-83"},  # XSS
    {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},  # path traversal
    {"CWE-90"},  # LDAP injection
    {"CWE-643"},  # XPath injection
    {"CWE-501"},  # trust boundary
]


def normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    cwe = str(cwe).strip().upper()
    if cwe.isdigit():
        cwe = f"CWE-{cwe}"
    return cwe.split(":")[0].strip()


def cwe_matches(found: str | None, expected: str) -> bool:
    found, expected = normalize_cwe(found), normalize_cwe(expected)
    if not found or not expected:
        return False
    if found == expected:
        return True
    return any(found in g and expected in g for g in CWE_GROUPS)


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, expected: bool, predicted: bool) -> None:
        if expected and predicted:
            self.tp += 1
        elif expected:
            self.fn += 1
        elif predicted:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def tpr(self) -> float:  # recall
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.tpr
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def youden(self) -> float:  # OWASP Benchmark's headline score: TPR - FPR
        return self.tpr - self.fpr

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 3), "recall": round(self.tpr, 3),
            "fpr": round(self.fpr, 3), "f1": round(self.f1, 3), "score": round(self.youden, 3),
        }


def score(cases: list, predictions: dict[str, bool]) -> tuple[Counts, dict[str, Counts]]:
    """cases: objects with .name, .category, .vulnerable. predictions: name -> flagged."""
    overall = Counts()
    per_cat: dict[str, Counts] = defaultdict(Counts)
    for c in cases:
        if c.name not in predictions:
            continue
        overall.add(c.vulnerable, predictions[c.name])
        per_cat[c.category].add(c.vulnerable, predictions[c.name])
    return overall, dict(sorted(per_cat.items()))
