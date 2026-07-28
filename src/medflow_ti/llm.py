from __future__ import annotations

import re

from groq import APIError as GroqAPIError
from groq import Groq
from openai import APIError as OpenAIAPIError
from openai import OpenAI


class LLMError(RuntimeError):
    pass


class GroqLLM:
    def __init__(
        self,
        api_key: str | None,
        model: str,
        hide_reasoning: bool = False,
        reasoning_effort: str | None = None,
        max_completion_tokens: int = 2048,
        user_only: bool = False,
    ) -> None:
        if not api_key:
            raise RuntimeError("Missing Groq API key. Set GroqAPIKey or GROQ_API_KEY in .env.")
        self.model = model
        self.hide_reasoning = hide_reasoning
        self.reasoning_effort = reasoning_effort
        self.max_completion_tokens = max_completion_tokens
        self.user_only = user_only
        self.client = Groq(api_key=api_key)

    def generate(self, prompt: str) -> str:
        system_instruction = (
            "You are a concise healthcare cybersecurity assistant. "
            "Use only the provided retrieved context."
        )
        messages = (
            [
                {
                    "role": "user",
                    "content": f"{system_instruction}\n\n{prompt}",
                }
            ]
            if self.user_only
            else [
                {
                    "role": "system",
                    "content": system_instruction,
                },
                {"role": "user", "content": prompt},
            ]
        )
        request = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "max_completion_tokens": self.max_completion_tokens,
        }
        if self.hide_reasoning:
            request["reasoning_format"] = "hidden"
        if self.reasoning_effort:
            request["reasoning_effort"] = self.reasoning_effort
        response = self.client.chat.completions.create(**request)
        return strip_thinking(response.choices[0].message.content or "")


class LocalQwenLLM:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "local",
        max_completion_tokens: int = 2048,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_completion_tokens = max_completion_tokens
        self.client = OpenAI(
            api_key=api_key or "local",
            base_url=self.base_url,
            timeout=300.0,
        )

    def generate(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a concise healthcare cybersecurity assistant. "
                        "Use only the provided retrieved context."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_completion_tokens=self.max_completion_tokens,
        )
        return strip_thinking(response.choices[0].message.content or "")


def strip_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>\s*", "", text, flags=re.DOTALL).strip()


def make_llm(
    provider: str,
    groq_api_key: str | None,
    llama_model: str,
    qwen_model: str,
    gpt_oss_model: str = "openai/gpt-oss-120b",
    max_completion_tokens: int = 2048,
    local_qwen_base_url: str = "http://127.0.0.1:8080/v1",
    local_qwen_model: str = "qwen-local",
    local_qwen_api_key: str = "local",
):
    if provider in {"gpt_oss", "gpt-oss"}:
        return GroqLLM(
            groq_api_key,
            gpt_oss_model,
            hide_reasoning=True,
            reasoning_effort="medium",
            max_completion_tokens=max_completion_tokens,
        )
    if provider == "llama":
        return GroqLLM(groq_api_key, llama_model, max_completion_tokens=max_completion_tokens)
    if provider in {"qwen", "groq"}:
        return GroqLLM(
            groq_api_key,
            qwen_model,
            hide_reasoning=True,
            reasoning_effort="none",
            max_completion_tokens=max_completion_tokens,
            user_only=True,
        )
    if provider in {"local_qwen", "local-qwen"}:
        return LocalQwenLLM(
            base_url=local_qwen_base_url,
            model=local_qwen_model,
            api_key=local_qwen_api_key,
            max_completion_tokens=max_completion_tokens,
        )
    raise ValueError(
        f"Unknown LLM provider '{provider}'. Choose gpt_oss, llama, qwen, or local_qwen."
    )


def is_llm_api_error(exc: Exception) -> bool:
    return isinstance(exc, (GroqAPIError, OpenAIAPIError))
