"""
Provider-agnostic chat client. Anything that speaks the OpenAI
chat-completions shape works here unchanged -- Alibaba Model Studio
(Qwen) today, Ollama later, by swapping env vars only.

    Alibaba Model Studio (international, Singapore workspace):
        STAGE4_LLM_BASE_URL=https://<workspace-id>.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1
        STAGE4_LLM_API_KEY=<your dashscope api key>
        STAGE4_LLM_MODEL=qwen-turbo        # small + fast; swap to qwen-plus if you need more reasoning depth

    Ollama (local, once you're off the free trial):
        STAGE4_LLM_BASE_URL=http://localhost:11434/v1
        STAGE4_LLM_API_KEY=ollama           # unused but the client requires *something*
        STAGE4_LLM_MODEL=qwen2.5:3b-instruct

No API key configured -> falls back to a deterministic mock so the ReAct
loop's control flow can be exercised and demoed without spending a token
or needing credentials yet.
"""

from __future__ import annotations

import json
import os


class LLMClient:
    def __init__(self):
        self.base_url = os.environ.get("STAGE4_LLM_BASE_URL")
        self.api_key = os.environ.get("STAGE4_LLM_API_KEY")
        self.model = os.environ.get("STAGE4_LLM_MODEL", "qwen-turbo")
        self._client = None
        if self.base_url and self.api_key:
            from openai import OpenAI  # pip install openai
            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key)

    @property
    def is_mock(self) -> bool:
        return self._client is None

    def chat_json(self, messages: list[dict]) -> dict:
        """Sends the conversation, expects the model to reply with exactly
        one JSON object (no prose around it), returns it parsed. Raises
        ValueError on malformed output so the caller can retry/bail
        instead of silently trusting garbage."""
        if self._client is None:
            return _mock_reply(messages)

        resp = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.1,  # this is a triage decision, not a creative one
            response_format={"type": "json_object"},
        )
        raw = resp.choices[0].message.content
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"model did not return valid JSON: {raw!r}") from e


def _mock_reply(messages: list[dict]) -> dict:
    """Deterministic stand-in used when no API key is set. Lets you run
    demo.py and see the full tool-call loop execute before you've activated
    Alibaba Model Studio. Not meant to simulate real reasoning quality."""
    turn = sum(1 for m in messages if m["role"] == "tool")
    if turn == 0:
        return {
            "action": "request_dynamic_trace",
            "args": {"focus": "network"},
            "reason": "rule hits mention a beacon but confidence is borderline; checking live traffic shape before concluding",
        }
    return {
        "action": "conclude",
        "verdict": "suspicious",
        "confidence": 0.62,
        "attck": ["T1071", "TA0011"],
        "rationale": "Mock reply: beacon pattern present but no corroborating dynamic trace -- flagged suspicious pending analyst review.",
    }
