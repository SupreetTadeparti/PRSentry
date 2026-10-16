"""Runtime configuration, read from environment variables (set by action.yml)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name, "").strip()
    return value or default


@dataclass
class Config:
    # LLM (any OpenAI-compatible endpoint: UF NaviGator, OpenAI, a local server, ...)
    llm_api_key: str = field(default_factory=lambda: _env("LLM_API_KEY"))
    # NaviGator's OpenAI-compatible endpoint; verify against UF's docs.
    llm_base_url: str = field(default_factory=lambda: _env("LLM_BASE_URL", "https://api.ai.it.ufl.edu/v1"))
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL", "gpt-4o"))
    # "openai" for any OpenAI-compatible API, "anthropic" for the Claude API
    llm_provider: str = field(default_factory=lambda: _env("LLM_PROVIDER", "openai"))

    # Semgrep rulesets to run
    semgrep_configs: list[str] = field(
        default_factory=lambda: _env("SEMGREP_CONFIGS", "p/security-audit,p/secrets,p/owasp-top-ten").split(",")
    )

    # Filtering
    min_confidence: float = field(default_factory=lambda: float(_env("MIN_CONFIDENCE", "0.6")))
    max_comments: int = field(default_factory=lambda: int(_env("MAX_COMMENTS", "15")))
    context_lines: int = 20
    enable_llm_scan: bool = field(default_factory=lambda: _env("ENABLE_LLM_SCAN", "true").lower() == "true")
    max_hunks: int = field(default_factory=lambda: int(_env("MAX_HUNKS", "30")))

    # GitHub
    github_token: str = field(default_factory=lambda: _env("GITHUB_TOKEN"))
    github_repository: str = field(default_factory=lambda: _env("GITHUB_REPOSITORY"))
    github_api_url: str = field(default_factory=lambda: _env("GITHUB_API_URL", "https://api.github.com"))
