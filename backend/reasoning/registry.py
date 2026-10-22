"""Picks the Reasoner named by REASONER_BACKEND (dashboard setting overrides the environment)."""
from importlib import import_module

from django.conf import settings

_BACKENDS = {
    "rules": "reasoning.rule_reasoner.RuleReasoner",
    "hybrid": "reasoning.hybrid_reasoner.HybridReasoner",   # Stage 4: rule engine + active lists + agentic loop
    # Stage 4 decision goes here later, e.g.:
    # "ml": "reasoning.ml_reasoner.MLReasoner",
    # "slm": "reasoning.slm_reasoner.SLMReasoner",
}


def current_backend() -> str:
    from dashboard.settings_store import get_setting

    return get_setting("reasoner_backend", settings.SENTINEL["REASONER_BACKEND"])


def get_reasoner(name: str | None = None):
    if name is None:
        name = current_backend()
    path = _BACKENDS.get(name)
    if path is None:
        # Unknown or not-yet-decided backends fall back to the rule engine instead of breaking the pipeline.
        path = _BACKENDS["rules"]
    module_path, cls_name = path.rsplit(".", 1)
    return getattr(import_module(module_path), cls_name)()
