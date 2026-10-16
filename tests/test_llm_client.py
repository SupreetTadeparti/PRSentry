from types import SimpleNamespace

import pytest

from reviewer.config import Config
from reviewer.llm_client import LLMConfigError, OpenAICompatibleClient


def _client(model, available):
    cfg = Config()
    cfg.llm_api_key, cfg.llm_model = "k", model
    c = OpenAICompatibleClient(cfg)
    c.client = SimpleNamespace(
        base_url="https://example/v1",
        models=SimpleNamespace(list=lambda: [SimpleNamespace(id=m) for m in available]),
    )
    return c


def test_check_model_lists_alternatives_when_model_missing():
    with pytest.raises(LLMConfigError) as e:
        _client("gpt-4o", ["llama-3.3-70b-instruct", "gpt-oss-120b"]).check_model()
    assert "gpt-oss-120b, llama-3.3-70b-instruct" in str(e.value)


def test_check_model_passes_when_available():
    _client("gpt-oss-120b", ["gpt-oss-120b"]).check_model()
