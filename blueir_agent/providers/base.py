from dataclasses import dataclass
from typing import Protocol


@dataclass
class LLMMessage:
    role: str
    content: str


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, messages: list[LLMMessage], *, temperature: float = 0.2) -> str:
        ...
