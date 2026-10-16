"""Helpers for pulling numbered source context around a line range."""
from __future__ import annotations

import os
from functools import lru_cache


@lru_cache(maxsize=256)
def read_lines(root: str, path: str) -> tuple[str, ...]:
    full = os.path.join(root, path)
    try:
        with open(full, encoding="utf-8", errors="replace") as f:
            return tuple(f.read().splitlines())
    except OSError:
        return ()


def numbered_context(root: str, path: str, start: int, end: int, radius: int = 20, mark: bool = True) -> str:
    lines = read_lines(root, path)
    if not lines:
        return "(file not readable)"
    lo = max(1, start - radius)
    hi = min(len(lines), end + radius)
    out = []
    for no in range(lo, hi + 1):
        prefix = ">>" if mark and start <= no <= end else "  "
        out.append(f"{prefix}{no:5d}: {lines[no - 1]}")
    return "\n".join(out)
