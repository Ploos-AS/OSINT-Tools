from __future__ import annotations

from datetime import datetime, timezone

from .providers.base import ProviderError
from .providers.registry import ProviderRegistry
from .storage import Store


def execute_provider(store: Store, registry: ProviderRegistry, target_id: int, provider_id: str, operation: str) -> dict:
    target = store.get_target(target_id)
    if target is None:
        raise ProviderError("target_not_found", "target not found", status=404)
    provider = registry.get(provider_id)
    if provider is None:
        raise ProviderError("unknown_provider", "provider not found", status=404)
    if operation not in provider.operations:
        raise ProviderError("unknown_operation", "provider operation not found", status=404)
    if target["type"] not in provider.supported_target_types:
        raise ProviderError("unsupported_target_type", "target type is not supported by provider", status=422)
    if hasattr(provider, "enabled") and not provider.enabled():
        raise ProviderError("provider_disabled", "provider is disabled", status=409)
    if not provider.configured():
        raise ProviderError("provider_not_configured", "provider is not configured", status=409)

    collected_at = datetime.now(timezone.utc).isoformat()
    result = provider.execute(operation, target)
    provenance = {
        "provider": provider.id,
        "operation": operation,
        "target": {"id": target["id"], "type": target["type"], "normalized": target["normalized"]},
        "collected_at": collected_at,
        "upstream_status": result.upstream_status,
        "rate_limit": result.rate_limit,
        "provider_metadata": result.metadata,
    }
    artifact = store.add_artifact(target["case_id"], target_id, f"provider:{provider.id}:{operation}", provider.id, {"result": result.data, "provenance": provenance})
    return {"artifact": artifact}
