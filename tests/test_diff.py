import subprocess

from reviewer.diff import get_changed_files, parse_diff

DIFF = """\
diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,6 @@
 import sqlite3
+API_KEY = "sk-live-123"

 def get_user(name):
-    return db.execute("SELECT * FROM users WHERE name = ?", (name,))
+    q = "SELECT * FROM users WHERE name = '" + name + "'"
+    return db.execute(q)
@@ -20,2 +22,3 @@ def other():
     pass
+    eval(input())
diff --git a/package-lock.json b/package-lock.json
--- a/package-lock.json
+++ b/package-lock.json
@@ -1 +1 @@
-{}
+{"a": 1}
diff --git a/old.py b/old.py
--- a/old.py
+++ /dev/null
@@ -1 +0,0 @@
-print("bye")
"""


def test_parse_diff_tracks_new_line_numbers():
    files = parse_diff(DIFF)
    assert list(files) == ["app.py"]  # lockfile skipped, deleted file ignored
    f = files["app.py"]
    assert [h.start for h in f.hunks] == [1, 22]
    assert f.hunks[0].lines == [
        (2, 'API_KEY = "sk-live-123"'),
        (5, "    q = \"SELECT * FROM users WHERE name = '\" + name + \"'\""),
        (6, "    return db.execute(q)"),
    ]
    assert f.hunks[1].lines == [(23, "    eval(input())")]
    assert f.added_lines == {2, 5, 6, 23}


def test_removal_only_hunks_are_dropped():
    diff = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1 @@\n keep\n-gone\n"
    assert parse_diff(diff) == {}


def test_get_changed_files_on_real_repo(tmp_path):
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    (tmp_path / "a.py").write_text("x = 1\n")
    git("add", ".")
    git("commit", "-qm", "base")
    git("checkout", "-qb", "feature")
    (tmp_path / "a.py").write_text("x = 1\npassword = 'hunter2'\n")
    git("commit", "-qam", "change")

    files = get_changed_files(str(tmp_path), "main")
    assert files["a.py"].added_lines == {2}
