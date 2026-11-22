"""DeepSeek adapter for explanations, via DeepSeek's Anthropic-compatible endpoint.

DeepSeek (model id ``deepseek-flash``) exposes an Anthropic-compatible Messages
API at ``https://api.deepseek.com/anthropic``, so this reuses the official
``anthropic`` SDK (the same optional ``[ai]`` extra) with a ``base_url`` instead
of adding a second SDK.

It differs from the Anthropic adapter in request *shape* only: the compat
endpoint does not offer Anthropic's native structured output (``output_config``),
reasoning ``effort``, or the server-side ``fallbacks`` beta, so this sends a plain
``messages.create`` and places the required JSON schema in the system prompt. The
explanation service validates the returned text against the same Pydantic
contract and grounding rules regardless of provider, so correctness does not
depend on the model obeying the schema.

Security: the API key and base URL come only from backend settings, never from
analysed content; nothing here logs the key, headers, or request content, and the
model is given no tools.
"""

from __future__ import annotations

import importlib
import json
from types import ModuleType
from typing import Any

from app.services.explanations._sdk_support import invoke_messages, response_from_message
from app.services.explanations.provider import (
    ProviderError,
    ProviderErrorCode,
    ProviderRequest,
    ProviderResponse,
)

_SCHEMA_INSTRUCTION = (
    "\n\nReturn a single JSON object and nothing else — no markdown, no code "
    "fences, no commentary. It must conform exactly to this JSON schema:\n{schema}"
)


class DeepSeekExplanationProvider:
    name = "deepseek"

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None,
        base_url: str | None,
        timeout_seconds: float,
        max_retries: int,
        client: Any | None = None,
        sdk: ModuleType | Any | None = None,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self._base_url = base_url
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._client = client
        self._sdk = sdk

    def _module(self) -> Any:
        if self._sdk is None:
            try:
                self._sdk = importlib.import_module("anthropic")
            except ImportError as exc:
                raise ProviderError(ProviderErrorCode.NOT_INSTALLED) from exc
        return self._sdk

    def _get_client(self, sdk: Any) -> Any:
        if self._client is None:
            if not self._api_key or not (self._base_url or "").strip():
                # DeepSeek needs both an API key and its Anthropic-compatible base URL.
                raise ProviderError(ProviderErrorCode.NOT_CONFIGURED)
            self._client = sdk.Anthropic(
                api_key=self._api_key,
                base_url=self._base_url,
                timeout=self._timeout,
                max_retries=self._max_retries,
            )
        return self._client

    def generate(self, request: ProviderRequest) -> ProviderResponse:
        sdk = self._module()
        client = self._get_client(sdk)
        system = request.system + _SCHEMA_INSTRUCTION.format(
            schema=json.dumps(request.json_schema, sort_keys=True)
        )
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": request.max_output_tokens,
            "system": system,
            "messages": [{"role": "user", "content": request.user}],
        }
        response = invoke_messages(sdk, lambda: client.messages.create(**kwargs))
        return response_from_message(response, self.model)


__all__ = ["DeepSeekExplanationProvider"]
