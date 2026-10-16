"""Work out which files and lines a PR changed, using `git diff`."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# Files we never scan (generated, vendored, binary-ish)
SKIP_SUFFIXES = (".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip")
SKIP_PARTS = ("node_modules/", "vendor/", "dist/", "build/", ".git/")
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "go.sum", "composer.lock"}


@dataclass
class Hunk:
    path: str
    start: int  # first line number in the new file
    lines: list[tuple[int, str]] = field(default_factory=list)  # (new line no, text) for added lines

    @property
    def end(self) -> int:
        return self.lines[-1][0] if self.lines else self.start

    def text(self) -> str:
        return "\n".join(f"{no}: {txt}" for no, txt in self.lines)


@dataclass
class ChangedFile:
    path: str
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def added_lines(self) -> set[int]:
        return {no for h in self.hunks for no, _ in h.lines}


def should_skip(path: str) -> bool:
    return (
        path.endswith(SKIP_SUFFIXES)
        or path.rsplit("/", 1)[-1] in SKIP_NAMES
        or any(path.startswith(p) or f"/{p}" in path for p in SKIP_PARTS)
    )


def parse_diff(diff_text: str) -> dict[str, ChangedFile]:
    """Parse a unified diff into added-line hunks per file (new-file line numbers)."""
    files: dict[str, ChangedFile] = {}
    current: ChangedFile | None = None
    hunk: Hunk | None = None
    new_line = 0

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":  # deleted file
                current = None
                continue
            path = target[2:] if target.startswith("b/") else target
            current = None if should_skip(path) else files.setdefault(path, ChangedFile(path))
            hunk = None
            continue
        if raw.startswith("--- ") or raw.startswith("diff --git") or raw.startswith("index "):
            continue
        m = HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(1))
            if current is not None:
                hunk = Hunk(current.path, new_line)
                current.hunks.append(hunk)
            continue
        if current is None or hunk is None:
            continue
        if raw.startswith("+"):
            hunk.lines.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            pass  # removed line: new-file counter doesn't advance
        elif raw.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:
            new_line += 1  # context line

    # Drop hunks that only removed code
    for f in files.values():
        f.hunks = [h for h in f.hunks if h.lines]
    return {p: f for p, f in files.items() if f.hunks}


def git_diff(repo_path: str, base: str, head: str = "HEAD") -> str:
    """Diff of `head` against the merge-base with `base` (what a PR shows)."""
    result = subprocess.run(
        ["git", "-C", repo_path, "diff", "--no-color", "--unified=3", f"{base}...{head}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return result.stdout


def get_changed_files(repo_path: str, base: str, head: str = "HEAD") -> dict[str, ChangedFile]:
    return parse_diff(git_diff(repo_path, base, head))
