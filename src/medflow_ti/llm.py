from __future__ import annotations

import re

from groq import APIError as GroqAPIError
from groq import Groq


class LLMError(RuntimeError):
    pass


class GroqLLM:
    def __init__(self, api_key: str | None, model: str, hide_reasoning: bool = False) -> None:
        if not api_key:
            raise RuntimeError("Missing Groq API key. Set GroqAPIKey or GROQ_API_KEY in .env.")
        self.model = model
        self.hide_reasoning = hide_reasoning
        self.client = Groq(api_key=api_key)

    def generate(self, prompt: str) -> str:
        request = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a concise healthcare cybersecurity assistant. Use only the provided retrieved context.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_completion_tokens": 2048,
        }
        if self.hide_reasoning:
            request["reasoning_format"] = "hidden"
        response = self.client.chat.completions.create(**request)
        return strip_thinking(response.choices[0].message.content or "")


def strip_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>\s*", "", text, flags=re.DOTALL).strip()


def make_llm(provider: str, groq_api_key: str | None, llama_model: str, qwen_model: str):
    if provider == "llama":
        return GroqLLM(groq_api_key, llama_model)
    if provider in {"qwen", "groq"}:
        return GroqLLM(groq_api_key, qwen_model, hide_reasoning=True)
    raise ValueError(f"Unknown LLM provider '{provider}'. Choose llama or qwen.")


def is_llm_api_error(exc: Exception) -> bool:
    return isinstance(exc, GroqAPIError)
