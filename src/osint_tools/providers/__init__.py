from .base import ProviderError, ProviderResult
from .ipinfo import IPInfoProvider
from .registry import ProviderRegistry


def builtin_registry(env=None) -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(IPInfoProvider(env=env))
    return registry


__all__ = ["ProviderError", "ProviderResult", "ProviderRegistry", "builtin_registry"]
