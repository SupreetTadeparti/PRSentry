from bench.owasp import TestCase as Case
from bench.owasp import load_cases, sample_cases, sanitize
from bench.score import cwe_matches, score


def test_cwe_matching_uses_groups():
    assert cwe_matches("CWE-89", "CWE-89")
    assert cwe_matches("89", "CWE-89")
    assert cwe_matches("CWE-328", "CWE-327")  # weak hash ~ weak crypto
    assert not cwe_matches("CWE-79", "CWE-89")
    assert not cwe_matches(None, "CWE-89")


def test_score_confusion_matrix():
    cases = [Case("t1", "sqli", True, "CWE-89", ""), Case("t2", "sqli", False, "CWE-89", ""),
             Case("t3", "xss", True, "CWE-79", ""), Case("t4", "xss", False, "CWE-79", "")]
    overall, per_cat = score(cases, {"t1": True, "t2": True, "t3": False, "t4": False})
    assert (overall.tp, overall.fp, overall.fn, overall.tn) == (1, 1, 1, 1)
    assert per_cat["sqli"].tpr == 1.0 and per_cat["sqli"].fpr == 1.0
    assert per_cat["xss"].youden == 0.0


def test_sanitize_removes_category_hint():
    src = '@WebServlet(value = "/sqli-00/BenchmarkTest00008")'
    assert sanitize(src) == '@WebServlet(value = "/test/BenchmarkTest00008")'


def test_load_and_stratified_sample(tmp_path):
    testcode = tmp_path / "src/main/java/org/owasp/benchmark/testcode"
    testcode.mkdir(parents=True)
    rows = ["# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1"]
    for i in range(40):
        name = f"BenchmarkTest{i:05d}"
        cat = ["sqli", "xss"][i % 2]
        rows.append(f"{name},{cat},{'true' if i % 4 < 2 else 'false'},{89 if cat == 'sqli' else 79}")
        (testcode / f"{name}.java").write_text("class X {}")
    (tmp_path / "expectedresults-1.2.csv").write_text("\n".join(rows))

    cases = load_cases(str(tmp_path))
    assert len(cases) == 40 and cases[0].cwe == "CWE-89"
    picked = sample_cases(cases, 8)
    buckets = {(c.category, c.vulnerable) for c in picked}
    assert len(picked) == 8 and len(buckets) == 4  # every (category, label) bucket represented
    assert sample_cases(cases, 8) == picked  # deterministic for a given seed
