from .abuseipdb import AbuseIPDBProvider
from .base import ProviderError, ProviderResult
from .ipinfo import IPInfoProvider
from .registry import ProviderRegistry
from .shodan import ShodanProvider
from .virustotal import VirusTotalProvider


def builtin_registry(env=None) -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(IPInfoProvider(env=env))
    registry.register(VirusTotalProvider(env=env))
    registry.register(AbuseIPDBProvider(env=env))
    registry.register(ShodanProvider(env=env))
    return registry


__all__ = ["ProviderError", "ProviderResult", "ProviderRegistry", "builtin_registry"]
