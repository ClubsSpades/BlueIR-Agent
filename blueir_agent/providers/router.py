from blueir_agent.providers.base import LLMMessage, LLMProvider


class ModelRouter:
    def __init__(self, providers: list[LLMProvider]) -> None:
        self.providers = providers

    def complete(self, messages: list[LLMMessage], *, task: str, temperature: float = 0.2) -> str:
        # MVP: first available provider. Later this becomes task/cost/privacy routing.
        for provider in self.providers:
            available = getattr(provider, "available", True)
            if available:
                return provider.complete(messages, temperature=temperature)
        return ""
