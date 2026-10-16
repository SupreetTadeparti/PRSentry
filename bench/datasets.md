# Benchmark datasets

## OWASP Benchmark (primary)

- Repo: https://github.com/OWASP-Benchmark/BenchmarkJava
- ~2,740 small Java servlets. Each one is labeled in `expectedresults-1.2.csv` as **truly vulnerable** or
  **safe** for one CWE (SQLi, XSS, command injection, path traversal, LDAP/XPath injection, weak crypto,
  weak hashing, weak randomness, insecure cookies, trust boundary).
- About half the cases are *safe look-alikes* (e.g. tainted data that's overwritten before use), which is
  exactly what makes static analyzers produce false alarms. That's why it's a good test of whether LLM
  triage reduces false positives without losing real issues.
- Scoring follows the OWASP Benchmark convention: a case counts as "flagged" only if a finding's CWE
  matches the expected one (related CWEs are grouped; see `score.py`). Headline score = TPR − FPR.
- The servlet URL in each file names its category (`/sqli-00/...`). `owasp.py` strips it so the LLM
  can't read the answer off the page.

## Demo app (qualitative)

`demo/vulnerable_app.py` has 7 planted issues plus 1 safe decoy, with an answer key in the docstring.
Two of the issues (missing auth, IDOR) are logic bugs that rule-based tools can't detect, so they show
what the LLM diff scan adds.

## Ideas for more datasets

- Python: hand-label a deliberately vulnerable Flask/Django app (e.g. from OWASP's vulnerable-apps list).
- JavaScript: OWASP Juice Shop, whose challenges are documented, so they can serve as labels.
- Real CVE fix commits: diff the vulnerable version against the fix and check the bot flags the vulnerable side.
