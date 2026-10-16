"""Thin LLM wrapper: send a prompt, get back a JSON object matching a schema.

Two backends:
  * "openai"    - any OpenAI-compatible API (UF NaviGator, OpenAI, Ollama, ...)
  * "anthropic" - the Claude API, via the official `anthropic` SDK
"""
from __future__ import annotations

import ast
import json
import logging
import re
import time
from typing import Protocol

from .config import Config

log = logging.getLogger(__name__)


class LLMError(RuntimeError):
    """A single call failed (bad JSON, refusal). The run continues without that result."""


class LLMConfigError(RuntimeError):
    """The key, endpoint or model is wrong. Every call would fail, so the run stops."""


class LLMClient(Protocol):
    def complete_json(self, system: str, user: str, schema: dict) -> dict: ...


_UNQUOTED_KEY = re.compile(r'([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:)')


def _extract_json(text: str) -> dict:
    """Parse JSON from a model reply, tolerating fences, leading prose, and the near-JSON
    that open models often emit (single quotes, True/False/None, unquoted keys)."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Only unwrap a fence that encloses the whole reply. Fences can also appear *inside*
    # JSON string values (e.g. a "fix" containing a code block), and those must be left alone.
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        text = text[start : end + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError as first_err:
        # Python-literal style: {'is_vulnerable': True, ...}
        try:
            value = ast.literal_eval(text)
            if isinstance(value, dict):
                return value
        except (ValueError, SyntaxError):
            pass
        # JS-object style: {is_vulnerable: true, ...}
        try:
            return json.loads(_UNQUOTED_KEY.sub(r'\1"\2"\3', text))
        except json.JSONDecodeError:
            raise first_err from None


class OpenAICompatibleClient:
    def __init__(self, cfg: Config):
        from openai import OpenAI

        self.client = OpenAI(api_key=cfg.llm_api_key, base_url=cfg.llm_base_url, max_retries=3)
        self.model = cfg.llm_model
        self._json_mode = True  # turned off if the server rejects response_format

    def check_model(self) -> None:
        """Fail fast with a helpful message if the key can't use the configured model."""
        from openai import APIStatusError, AuthenticationError

        try:
            available = sorted(m.id for m in self.client.models.list())
        except AuthenticationError as e:
            raise LLMConfigError(f"LLM API key was rejected by {self.client.base_url}: {e}") from e
        except APIStatusError as e:
            log.info("could not list models (%s); skipping model check", e.status_code)
            return
        if available and self.model not in available:
            raise LLMConfigError(
                f"Model '{self.model}' is not available for this API key. "
                f"Set the LLM_MODEL variable (or the llm-model input) to one of: {', '.join(available)}"
            )

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        from openai import AuthenticationError, BadRequestError, NotFoundError, PermissionDeniedError

        # Not every OpenAI-compatible server supports json_schema, so the schema goes in the prompt
        system = f"{system}\n\nRespond with ONLY a JSON object matching this JSON Schema:\n{json.dumps(schema)}"
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        last_err: Exception | None = None
        for attempt in range(3):
            kwargs = {"model": self.model, "messages": messages, "temperature": 0}
            if self._json_mode:
                kwargs["response_format"] = {"type": "json_object"}
            try:
                resp = self.client.chat.completions.create(**kwargs)
            except (AuthenticationError, PermissionDeniedError, NotFoundError) as e:
                raise LLMConfigError(f"LLM request rejected ({e.status_code}): {e}") from e
            except BadRequestError as e:
                if self._json_mode and "response_format" in str(e):
                    log.info("server rejected response_format; falling back to prompt-only JSON")
                    self._json_mode = False
                    continue
                raise
            choice = resp.choices[0]
            content = choice.message.content or ""
            try:
                return _extract_json(content)
            except json.JSONDecodeError as e:
                last_err = e
                log.warning(
                    "bad JSON from model (attempt %d, finish_reason=%s): %r",
                    attempt + 1, choice.finish_reason, content[:300],
                )
                time.sleep(1)
        raise LLMError(f"model did not return valid JSON: {last_err}")


class AnthropicClient:
    def __init__(self, cfg: Config):
        import anthropic

        # Falls back to ANTHROPIC_API_KEY / `ant auth login` credentials when LLM_API_KEY is unset
        self.client = anthropic.Anthropic(api_key=cfg.llm_api_key or None, max_retries=3)
        self.model = cfg.llm_model

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        # Structured outputs guarantee schema-valid JSON. Current Claude models reject
        # `temperature`, so depth is controlled with `effort` instead.
        import anthropic

        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
                # Security code review can trip safety classifiers; let the API retry on a fallback model
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError, anthropic.NotFoundError) as e:
            raise LLMConfigError(f"Claude API request rejected ({e.status_code}): {e}") from e
        if response.stop_reason == "refusal":
            raise LLMError(f"model refused: {getattr(response.stop_details, 'category', None)}")
        text = next((b.text for b in response.content if b.type == "text"), "")
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise LLMError(f"model did not return valid JSON (stop_reason={response.stop_reason})") from e


def make_client(cfg: Config) -> LLMClient:
    if cfg.llm_provider == "anthropic":
        if not cfg.llm_model.startswith("claude"):
            cfg.llm_model = "claude-opus-5-5"  # LLM_MODEL still holds the OpenAI-side default
        return AnthropicClient(cfg)
    if not cfg.llm_api_key:
        raise LLMConfigError("LLM_API_KEY is not set (add it under Settings → Secrets and variables → Actions)")
    client = OpenAICompatibleClient(cfg)
    client.check_model()
    return client
