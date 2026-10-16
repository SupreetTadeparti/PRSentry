"""Thin LLM wrapper: send a prompt, get back a JSON object matching a schema.

Two backends:
  * "openai"    - any OpenAI-compatible API (UF NaviGator, OpenAI, Ollama, ...)
  * "anthropic" - the Claude API, via the official `anthropic` SDK
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Protocol

from .config import Config

log = logging.getLogger(__name__)


class LLMError(RuntimeError):
    pass


class LLMClient(Protocol):
    def complete_json(self, system: str, user: str, schema: dict) -> dict: ...


def _extract_json(text: str) -> dict:
    """Parse JSON from a model reply, tolerating ```json fences or leading prose."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


class OpenAICompatibleClient:
    def __init__(self, cfg: Config):
        from openai import OpenAI

        self.client = OpenAI(api_key=cfg.llm_api_key, base_url=cfg.llm_base_url, max_retries=3)
        self.model = cfg.llm_model
        self._json_mode = True  # turned off if the server rejects response_format

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        from openai import BadRequestError

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
            except BadRequestError as e:
                if self._json_mode and "response_format" in str(e):
                    log.info("server rejected response_format; falling back to prompt-only JSON")
                    self._json_mode = False
                    continue
                raise
            content = resp.choices[0].message.content or ""
            try:
                return _extract_json(content)
            except json.JSONDecodeError as e:
                last_err = e
                log.warning("bad JSON from model (attempt %d), retrying", attempt + 1)
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
        raise LLMError("LLM_API_KEY is not set")
    return OpenAICompatibleClient(cfg)
