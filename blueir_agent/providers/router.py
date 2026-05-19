from blueir_agent.providers.base import LLMMessage, LLMProvider
from blueir_agent.agent.roles import RoleConfig, load_roles_from_env
from typing import Optional


class ModelRouter:
    def __init__(self, providers: list[LLMProvider], roles: Optional[dict[str, RoleConfig]] = None) -> None:
        self.providers = providers
        self.roles = roles or load_roles_from_env()

    def complete(self, messages: list[LLMMessage], *, task: str, role: str = "report", temperature: float = 0.2) -> str:
        role_config = self.roles.get(role)
        preferred_provider = role_config.provider if role_config else ""
        preferred_model = role_config.model if role_config else ""

        provider = self._select_provider(preferred_provider)
        if provider:
            original_model = getattr(provider, "model", "")
            if preferred_model and hasattr(provider, "model"):
                provider.model = preferred_model
            try:
                return provider.complete(messages, temperature=temperature)
            finally:
                if original_model and hasattr(provider, "model"):
                    provider.model = original_model

        for provider in self.providers:
            available = getattr(provider, "available", True)
            if available:
                return provider.complete(messages, temperature=temperature)
        return ""

    def role_model(self, role: str) -> str:
        role_config = self.roles.get(role)
        if role_config:
            return f"{role_config.provider}/{role_config.model}"
        for provider in self.providers:
            if getattr(provider, "available", True):
                return f"{getattr(provider, 'name', 'provider')}/{getattr(provider, 'model', 'model')}"
        return "local-heuristic"

    def _select_provider(self, name: str) -> Optional[LLMProvider]:
        for provider in self.providers:
            if getattr(provider, "name", "") == name and getattr(provider, "available", True):
                return provider
        return None
