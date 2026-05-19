import json
import os
import urllib.error
import urllib.request
from typing import Optional

from blueir_agent.providers.base import LLMMessage


class DeepSeekProvider:
    name = "deepseek"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self.model = model or os.environ.get("BLUEIR_MODEL", "deepseek-v4-pro")
        self.base_url = (base_url or os.environ.get("BLUEIR_BASE_URL", "https://api.deepseek.com")).rstrip("/")
        self.timeout = timeout or int(os.environ.get("BLUEIR_TIMEOUT", "60"))

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.2) -> str:
        if not self.available:
            return ""

        payload = {
            "model": self.model,
            "messages": [{"role": msg.role, "content": msg.content} for msg in messages],
            "temperature": temperature,
            "stream": False,
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"DeepSeek API error {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"DeepSeek API network error: {exc.reason}") from exc

        return body["choices"][0]["message"].get("content", "").strip()
