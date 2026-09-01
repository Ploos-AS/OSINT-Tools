from __future__ import annotations

from .base import AVEngine


class AVRegistry:
    def __init__(self, engines=()):
        self._engines: dict[str, AVEngine] = {}
        for engine in engines: self.register(engine)

    def register(self, engine: AVEngine) -> None:
        if engine.id in self._engines: raise ValueError(f"duplicate antivirus engine: {engine.id}")
        self._engines[engine.id] = engine

    def get(self, engine_id: str) -> AVEngine | None: return self._engines.get(engine_id)
    def list(self) -> list[AVEngine]: return list(self._engines.values())
