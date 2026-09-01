from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisLimits:
    max_depth: int = 3
    max_members: int = 1000
    max_member_bytes: int = 25 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    max_ratio: float = 100.0
    max_image_pixels: int = 40_000_000
    max_metadata_bytes: int = 2 * 1024 * 1024


@dataclass
class AnalysisBudget:
    limits: AnalysisLimits
    members: int = 0
    expanded_bytes: int = 0

    def member(self) -> bool:
        if self.members >= self.limits.max_members:
            return False
        self.members += 1
        return True

    def allowance(self, compressed_size: int | None = None) -> tuple[int, str]:
        candidates = [(self.limits.max_member_bytes, "max_member_bytes"), (self.limits.max_total_bytes - self.expanded_bytes, "max_total_bytes")]
        if compressed_size is not None:
            ratio_bytes = max(1, int(compressed_size * self.limits.max_ratio))
            candidates.append((ratio_bytes, "max_compression_ratio"))
        return min(candidates, key=lambda item: item[0])
