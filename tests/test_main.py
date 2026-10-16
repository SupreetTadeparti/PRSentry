import json
import subprocess

from reviewer import main as main_mod
from reviewer import pipeline
from reviewer.models import Candidate

from .test_pipeline import APP, FakeLLM


def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    (repo / "README.md").write_text("hi\n")
    git("add", ".")
    git("commit", "-qm", "base")
    git("checkout", "-qb", "feature")
    (repo / "app.py").write_text(APP)
    git("add", ".")
    git("commit", "-qm", "add app")

    fake_semgrep = [Candidate(path="app.py", start_line=5, end_line=6, rule_id="sqli", message="sql", cwe="CWE-89")]
    monkeypatch.setattr(pipeline, "run_semgrep", lambda paths, configs, cwd: fake_semgrep)
    monkeypatch.setattr(main_mod, "make_client", lambda cfg: FakeLLM())
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

    out = tmp_path / "findings.json"
    code = main_mod.main(["--path", str(repo), "--base", "main", "--json-out", str(out), "--fail-on", "high"])

    assert code == 1  # a critical finding trips --fail-on high
    findings = json.loads(out.read_text())
    assert [(f["line"], f["severity"]) for f in findings] == [(5, "critical"), (9, "high")]
    assert "app.py:5" in capsys.readouterr().out
