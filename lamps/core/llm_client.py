from __future__ import annotations


class LLMClient:
    def __init__(self, api_key: str | None, api_base: str, model: str):
        self.api_key = api_key
        self.api_base = api_base
        self.model = model

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise RuntimeError("LLM_API_KEY is not configured.")
        try:
            from openai import OpenAI
        except Exception as exc:
            raise RuntimeError("The openai package is required for LLM API mode.") from exc

        client = OpenAI(api_key=self.api_key, base_url=self.api_base)
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.1,
        )
        return response.choices[0].message.content or ""

    def complete_or_default(self, system: str, user: str, default: str) -> str:
        if not self.available:
            return default
        try:
            return self.complete(system, user).strip() or default
        except Exception:
            return default
