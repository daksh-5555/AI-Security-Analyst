"""Optional LIVE DeepSeek smoke test — makes a real API call.

It is skipped unless BOTH are set:
  - DEEPSEEK_LIVE_TEST=1
  - LLM_API_KEY  (a real DeepSeek key)

Run it explicitly, never in ordinary CI:
  DEEPSEEK_LIVE_TEST=1 LLM_API_KEY=sk-... \
  LLM_PROVIDER=deepseek LLM_MODEL=deepseek-flash \
  LLM_BASE_URL=https://api.deepseek.com/anthropic \
  pytest tests/test_deepseek_live_smoke.py -q

It confirms the DeepSeek endpoint is reachable and returns text; it does not
assert exact content. The key is read from the environment and never printed.
"""

from __future__ import annotations

import os

import pytest

from app.services.explanations.deepseek_provider import DeepSeekExplanationProvider
from app.services.explanations.provider import ProviderRequest

pytestmark = pytest.mark.skipif(
    os.getenv("DEEPSEEK_LIVE_TEST") not in {"1", "true", "yes"}
    or not os.getenv("LLM_API_KEY"),
    reason="set DEEPSEEK_LIVE_TEST=1 and LLM_API_KEY to run the live DeepSeek smoke test",
)


def test_live_deepseek_returns_text() -> None:
    provider = DeepSeekExplanationProvider(
        model=os.getenv("LLM_MODEL", "deepseek-flash"),
        api_key=os.environ["LLM_API_KEY"],
        base_url=os.getenv("LLM_BASE_URL", "https://api.deepseek.com/anthropic"),
        timeout_seconds=60.0,
        max_retries=1,
    )
    request = ProviderRequest(
        system="You reply only with a single JSON object.",
        user='Return exactly {"ok": true} and nothing else.',
        json_schema={
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
        max_output_tokens=200,
    )
    response = provider.generate(request)
    assert isinstance(response.text, str) and response.text.strip()
    assert response.model
    assert response.input_tokens >= 0 and response.output_tokens >= 0
