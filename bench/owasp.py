"""Load and sample test cases from the OWASP Benchmark (Java) project.

    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava
"""
from __future__ import annotations

import csv
import glob
import os
import random
import re
from collections import defaultdict
from dataclasses import dataclass

TESTCODE_DIR = os.path.join("src", "main", "java", "org", "owasp", "benchmark", "testcode")

# Blind the test files so neither tool can tell it's looking at a benchmark:
#  - the servlet URL names the category (e.g. "/sqli-00/BenchmarkTest00001"), which hands over the answer
#  - the license header, package name and class name say "OWASP Benchmark", which the LLM picked up on
#    ("in this benchmark context the hash is merely written to a file")
_CATEGORY_URL = re.compile(r'"/[a-z]+-\d+/(BenchmarkTest\d+)"')
_LEADING_COMMENT = re.compile(r"\A\s*/\*.*?\*/\s*", re.DOTALL)
_TEST_NAME = re.compile(r"BenchmarkTest(\d+)")


def blind_name(name: str) -> str:
    return _TEST_NAME.sub(r"Handler\1", name)


@dataclass
class TestCase:
    name: str
    category: str
    vulnerable: bool
    cwe: str
    source_path: str

    @property
    def file(self) -> str:
        """Blinded file name the tools see, e.g. Handler00001.java."""
        return f"{blind_name(self.name)}.java"


def load_cases(benchmark_dir: str) -> list[TestCase]:
    matches = sorted(glob.glob(os.path.join(benchmark_dir, "expectedresults-*.csv")))
    if not matches:
        raise FileNotFoundError(f"no expectedresults-*.csv in {benchmark_dir}; is this a BenchmarkJava checkout?")
    cases = []
    with open(matches[-1], encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, category, real, cwe = (x.strip() for x in row[:4])
            path = os.path.join(benchmark_dir, TESTCODE_DIR, f"{name}.java")
            if os.path.exists(path):
                cases.append(TestCase(name, category, real.lower() == "true", f"CWE-{cwe}", path))
    return cases


def sample_cases(cases: list[TestCase], n: int, seed: int = 42, categories: list[str] | None = None) -> list[TestCase]:
    """Stratified sample: even across (category, vulnerable) buckets."""
    if categories:
        cases = [c for c in cases if c.category in categories]
    if n <= 0 or n >= len(cases):
        return cases
    buckets: dict[tuple[str, bool], list[TestCase]] = defaultdict(list)
    for c in cases:
        buckets[(c.category, c.vulnerable)].append(c)
    rng = random.Random(seed)
    for b in buckets.values():
        rng.shuffle(b)
    picked: list[TestCase] = []
    keys = sorted(buckets)
    i = 0
    while len(picked) < n and any(buckets.values()):  # round-robin over buckets
        b = buckets[keys[i % len(keys)]]
        if b:
            picked.append(b.pop())
        i += 1
    return sorted(picked, key=lambda c: c.name)


def sanitize(source: str) -> str:
    source = _CATEGORY_URL.sub(r'"/api/\1"', source)
    source = _LEADING_COMMENT.sub("", source, count=1)
    source = source.replace("org.owasp.benchmark.testcode", "com.example.webapp.handlers")
    source = source.replace("org.owasp.benchmark", "com.example.webapp")
    return blind_name(source)


def materialize(cases: list[TestCase], out_dir: str) -> None:
    """Copy sanitized test files into out_dir/<blinded name>.java."""
    os.makedirs(out_dir, exist_ok=True)
    for c in cases:
        with open(c.source_path, encoding="utf-8", errors="replace") as f:
            src = sanitize(f.read())
        with open(os.path.join(out_dir, c.file), "w", encoding="utf-8") as f:
            f.write(src)
