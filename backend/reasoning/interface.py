"""The Stage 4 seam (CONTRACTS section 9). Stage 4 (agentic reasoning) is on hold; do not put model code here."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ReasonContext:
    submission_id: str
    budget_seconds: int = 60
    loop_count: int = 0                 # how many verification loops already happened
    dynamic_allowed: bool = False       # DYNAMIC_ENABLED and the loop bound not reached
    device_info: dict[str, Any] = field(default_factory=dict)
    analyst_feedback: list[dict[str, Any]] = field(default_factory=list)  # past overrides for similar samples


class Reasoner(Protocol):
    name: str
    version: str

    def reason(self, evidence: dict[str, Any], ctx: ReasonContext) -> dict[str, Any]:
        """Return a Verdict dict (see shared/verdict.schema.json).

        Contract:
        - never raise; on failure return label="unknown", confidence=0.0 and say why in `explanation`
        - finish within ctx.budget_seconds
        - only reference evidence ids that exist in `evidence["signals"]`
        - set provider.name honestly
        """
        ...
