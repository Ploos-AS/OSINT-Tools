from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class ProviderError(Exception):
    """A safe, structured provider failure suitable for an API response."""

    def __init__(self, code: str, message: str, *, status: int, upstream_status: int | None = None, rate_limit: dict[str, str] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.upstream_status = upstream_status
        self.rate_limit = rate_limit or {}

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.upstream_status is not None:
            result["upstream_status"] = self.upstream_status
        if self.rate_limit:
            result["rate_limit"] = self.rate_limit
        return result


@dataclass(frozen=True)
class ProviderResult:
    data: Any
    upstream_status: int | None = None
    rate_limit: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    pivots: tuple["DerivedTarget", ...] = ()


@dataclass(frozen=True)
class DerivedTarget:
    value: str
    relation: str


class Provider(Protocol):
    id: str
    name: str
    description: str
    supported_target_types: tuple[str, ...]
    operations: tuple[str, ...]
    required_config: tuple[str, ...]
    default_timeout: float
    default_operation: str

    def configured(self) -> bool: ...
    def execute(self, operation: str, target: dict[str, Any], *, timeout: float | None = None) -> ProviderResult: ...

    def status(self) -> dict[str, Any]:
        """Public metadata only: configuration names, never their values."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.configured(),
            "configured": self.configured(),
            "required_configuration": list(self.required_config),
            "supported_target_types": list(self.supported_target_types),
            "operations": list(self.operations),
            "metadata": {"timeout_seconds": self.default_timeout},
        }
